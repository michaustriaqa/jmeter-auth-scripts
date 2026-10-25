/*
 * scripts/generic_oauth2_auth.groovy
 * -----------------------------------------------------------
 * Reusable generic OAuth2/OIDC login for JMeter.
 *
 * Covers any provider not already given its own named script in this
 * repo, as long as it exposes a standard OAuth2 token endpoint (Salesforce,
 * generic OIDC providers, a custom in-house auth server, etc.). The
 * provider-specific scripts (auth0_auth.groovy, okta_auth.groovy,
 * entra_id_auth.groovy, keycloak_auth.groovy, ping_auth.groovy) are this
 * same call shape with the URL/auth-style/defaults already filled in for
 * that provider; this script exposes those as config instead.
 *
 * Uses Java's built-in HTTP client - no AWS/SDK dependency at all.
 *
 * Features:
 * - Reads everything from JMeter properties (-J...) - the token URL,
 *   grant type, how the client authenticates, and even which JSON field
 *   holds the token, since some providers don't call it "access_token".
 * - Supports the Client Credentials grant (default) and the Resource
 *   Owner Password grant (set oauth2.grantType=password).
 * - Supports both ways providers expect the client to authenticate:
 *   "basic" (HTTP Basic auth header - Okta/Ping style) or "body"
 *   (client_id/client_secret as form fields - Auth0 style).
 * - Accepts arbitrary extra form parameters via JSON, for providers with
 *   a quirk the other options don't cover (e.g. a custom "realm" field).
 * - Authenticates once and shares the resulting token across every
 *   thread/sampler for the rest of the test via JMeter properties,
 *   instead of re-authenticating on every iteration/thread.
 * - Exports access_token (and expires_in) to JMeter variables.
 *
 * Required JMeter properties (pass via -J on the command line, or set in
 * user.properties):
 *   oauth2.tokenUrl        full token endpoint URL
 *   oauth2.clientId
 *   oauth2.clientSecret    omit only for a public client with no secret
 *
 * Optional:
 *   oauth2.grantType       "client_credentials" (default) or "password"
 *   oauth2.authStyle       "basic" (default) or "body" - how the client
 *                            authenticates (see above)
 *   oauth2.scope           space-separated scopes, only sent if set
 *   oauth2.audience        only sent if set (some providers require it)
 *   oauth2.username        required when grantType=password
 *   oauth2.password        required when grantType=password
 *   oauth2.tokenField      which JSON response field holds the bearer
 *                            token (default "access_token")
 *   oauth2.extraParams     JSON object string of additional form fields
 *                            to send, e.g. '{"realm":"my-realm"}'
 *
 * Placement:
 * - Add as a JSR223 Sampler/PreProcessor that runs once per thread
 *   (e.g. the first sampler in the Thread Group, outside any loop).
 *   The first thread to run it performs the real login; every other
 *   thread (and every later iteration) reuses the cached token.
 */

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.URLEncoder
import java.time.Duration
import java.util.Base64

import groovy.json.JsonSlurper


// =====[ FAST PATHS: SKIP RE-AUTH WHEN A TOKEN ALREADY EXISTS ]================

// 1. This thread already logged in earlier in the same script/loop.
if (vars.get("access_token")) {
    log.info("[generic_oauth2_auth] access_token already set for this thread, skipping re-auth.")
    return
}

// Property keys used to share the token across threads once logged in.
final PROP_ACCESS_TOKEN = "oauth2.access_token"

// 2. Another thread already logged in; reuse the shared token instead of
//    hitting the token endpoint again. The check-then-set below is
//    guarded by the synchronized block so only one thread ever performs
//    the real login.
synchronized (props) {
    def cachedAccessToken = props.get(PROP_ACCESS_TOKEN)
    if (cachedAccessToken) {
        vars.put("access_token", cachedAccessToken)
        log.info("[generic_oauth2_auth] Reusing token cached by another thread.")
        return
    }

    // =====[ CONFIGURATION ]====================================================

    def requireProp = { name ->
        def value = props.get(name)
        if (!value || value.trim().isEmpty()) {
            throw new RuntimeException("[generic_oauth2_auth] Missing required JMeter property: -J${name}=...")
        }
        value
    }

    def tokenUrl = requireProp("oauth2.tokenUrl")
    def clientId = requireProp("oauth2.clientId")
    def clientSecret = props.get("oauth2.clientSecret")
    def grantType = props.get("oauth2.grantType") ?: "client_credentials"
    def authStyle = props.get("oauth2.authStyle") ?: "basic"
    def scope = props.get("oauth2.scope")
    def audience = props.get("oauth2.audience")
    def tokenField = props.get("oauth2.tokenField") ?: "access_token"
    def extraParamsJson = props.get("oauth2.extraParams")

    if (authStyle != "basic" && authStyle != "body") {
        throw new RuntimeException("[generic_oauth2_auth] oauth2.authStyle must be \"basic\" or \"body\", got: ${authStyle}")
    }

    // =====[ HELPERS ]==========================================================

    def formEncode = { Map<String, String> params ->
        params.collect { k, v -> "${URLEncoder.encode(k, 'UTF-8')}=${URLEncoder.encode(v as String, 'UTF-8')}" }.join("&")
    }

    // =====[ MAIN AUTH FLOW ]===================================================

    def formParams = ["grant_type": grantType]

    if (authStyle == "body") {
        formParams["client_id"] = clientId
        if (clientSecret) {
            formParams["client_secret"] = clientSecret
        }
    }
    if (scope) {
        formParams["scope"] = scope
    }
    if (audience) {
        formParams["audience"] = audience
    }
    if (grantType == "password") {
        formParams["username"] = requireProp("oauth2.username")
        formParams["password"] = requireProp("oauth2.password")
    }
    if (extraParamsJson) {
        def extraParams = new JsonSlurper().parseText(extraParamsJson)
        extraParams.each { k, v -> formParams[k as String] = v as String }
    }

    def requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(tokenUrl))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .timeout(Duration.ofSeconds(15))

    if (authStyle == "basic") {
        if (!clientSecret) {
            throw new RuntimeException("[generic_oauth2_auth] oauth2.clientSecret is required when oauth2.authStyle=basic")
        }
        def basicAuth = Base64.encoder.encodeToString("${clientId}:${clientSecret}".getBytes("UTF-8"))
        requestBuilder.header("Authorization", "Basic ${basicAuth}")
    }

    def request = requestBuilder
            .POST(HttpRequest.BodyPublishers.ofString(formEncode(formParams)))
            .build()

    def httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build()

    def response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

    if (response.statusCode() < 200 || response.statusCode() >= 300) {
        throw new RuntimeException("[generic_oauth2_auth] Authentication failed (HTTP ${response.statusCode()}): ${response.body()}")
    }

    def result = new JsonSlurper().parseText(response.body())
    def token = result[tokenField]
    if (!token) {
        throw new RuntimeException("[generic_oauth2_auth] Authentication response did not contain a \"${tokenField}\" field: ${response.body()}")
    }

    // Share the token across every thread via properties, and expose it to
    // this thread's own samplers via JMeter variables.
    props.put(PROP_ACCESS_TOKEN, token as String)

    vars.put("access_token", token as String)
    if (result.expires_in) {
        vars.put("expires_in", result.expires_in as String)
    }

    log.info("[generic_oauth2_auth] Authentication successful. access_token stored as var/prop.")
}
