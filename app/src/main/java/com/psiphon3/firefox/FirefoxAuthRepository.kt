/*
 * Copyright (C) 2026 Glimpser
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Firefox Accounts sign-in. Security challenges are surfaced to the user; this
 * class intentionally does not automate or bypass anti-bot challenges.
 */
package com.psiphon3.firefox

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class FirefoxAuthRepository(
    private val sessionStore: FirefoxSessionStore,
) {
    sealed class LoginResult {
        data object SignedIn : LoginResult()
        data object NeedsEmailCode : LoginResult()
    }

    class AuthException(
        message: String,
        val challengeRequired: Boolean = false,
        val statusCode: Int? = null,
    ) : IOException(message)

    @Volatile private var pendingSessionToken: String? = null

    suspend fun beginLogin(email: String, password: String): LoginResult = withContext(Dispatchers.IO) {
        val cleanEmail = normalizeEmail(email)
        require(cleanEmail.isNotBlank()) { "Enter your Firefox Account email." }
        require(password.isNotEmpty()) { "Enter your password." }

        val requestBody = JSONObject()
            .put("email", cleanEmail)
            .put("authPW", deriveAuthPassword(cleanEmail, password))
            .put("verificationMethod", "email-2fa")

        val login = try {
            postJson("$FXA_API/account/login", requestBody)
        } catch (e: AuthException) {
            // Some account configurations reject the optional verificationMethod field.
            if (e.statusCode == 400) {
                postJson(
                    "$FXA_API/account/login",
                    JSONObject().put("email", cleanEmail).put("authPW", deriveAuthPassword(cleanEmail, password)),
                )
            } else {
                throw e
            }
        }

        val sessionToken = login.optString("sessionToken").takeIf { it.isNotBlank() }
            ?: throw AuthException("Firefox Accounts did not return a session.")
        if (!login.optBoolean("verified", false)) {
            pendingSessionToken = sessionToken
            LoginResult.NeedsEmailCode
        } else {
            completeLogin(sessionToken)
            LoginResult.SignedIn
        }
    }

    suspend fun verifyEmailCode(code: String) = withContext(Dispatchers.IO) {
        val sessionToken = pendingSessionToken
            ?: throw AuthException("The sign-in session expired. Start sign-in again.")
        val cleanCode = code.filterNot(Char::isWhitespace)
        require(cleanCode.isNotBlank()) { "Enter the verification code." }

        postJson(
            "$FXA_API/session/verify_code",
            JSONObject().put("code", cleanCode),
            sessionToken = sessionToken,
        )
        completeLogin(sessionToken)
        pendingSessionToken = null
    }

    fun isSignedIn(): Boolean = sessionStore.load() != null

    fun signOut() {
        pendingSessionToken = null
        sessionStore.clear()
    }

    private suspend fun completeLogin(sessionToken: String) {
        val token = postJson(
            "$FXA_API/oauth/token",
            JSONObject()
                .put("client_id", CLIENT_ID)
                .put("grant_type", "fxa-credentials")
                .put("scope", OAUTH_SCOPE)
                .put("access_type", "offline"),
            sessionToken = sessionToken,
        )
        val access = token.optString("access_token").takeIf { it.isNotBlank() }
            ?: throw AuthException("Firefox Accounts did not return an access token.")
        val refresh = token.optString("refresh_token").takeIf { it.isNotBlank() }
        val expiresIn = token.optLong("expires_in", DEFAULT_TOKEN_TTL).coerceAtLeast(60L)
        sessionStore.save(
            FirefoxSession(
                accessToken = access,
                refreshToken = refresh,
                expiresAtEpochSeconds = System.currentTimeMillis() / 1000 + expiresIn,
            ),
        )
    }

    private fun postJson(
        url: String,
        json: JSONObject,
        sessionToken: String? = null,
    ): JSONObject {
        val body = json.toString().toByteArray(Charsets.UTF_8)
        val httpUrl = url.toHttpUrlOrThrow()
        val request = Request.Builder()
            .url(httpUrl)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("User-Agent", USER_AGENT)
            .apply {
                if (sessionToken != null) {
                    val (tokenId, key) = deriveHawkCredentials(sessionToken)
                    header("Authorization", hawkHeader("POST", httpUrl, tokenId, key, body))
                }
            }
            .post(body.toRequestBody(JSON_MEDIA_TYPE))
            .build()

        FirefoxControlPlaneHttp.client.newCall(request).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (response.code == 406) {
                throw AuthException(
                    "Firefox Accounts requires a security challenge. This app will not bypass it automatically.",
                    challengeRequired = true,
                    statusCode = response.code,
                )
            }
            if (!response.isSuccessful) {
                val error = runCatching { JSONObject(text) }.getOrNull()
                val message = error?.optString("message")?.takeIf { it.isNotBlank() }
                    ?: "Firefox Accounts sign-in failed (HTTP ${response.code})."
                throw AuthException(message, statusCode = response.code)
            }
            return if (text.isBlank()) JSONObject() else JSONObject(text)
        }
    }

    private fun deriveAuthPassword(email: String, password: String): String {
        val salt = "${PROTOCOL_VERSION}quickStretch:$email".toByteArray(Charsets.UTF_8)
        val quick = pbkdf2HmacSha256(password.toByteArray(Charsets.UTF_8), salt, 1000, 32)
        return hkdf(quick, "${PROTOCOL_VERSION}authPW", 32).toHex()
    }

    private fun deriveHawkCredentials(sessionTokenHex: String): Pair<String, ByteArray> {
        val expanded = hkdf(sessionTokenHex.hexToBytes(), "${PROTOCOL_VERSION}sessionToken", 64)
        return expanded.copyOfRange(0, 32).toHex() to expanded.copyOfRange(32, 64)
    }

    private fun hawkHeader(
        method: String,
        url: HttpUrl,
        tokenId: String,
        hmacKey: ByteArray,
        body: ByteArray,
    ): String {
        val timestamp = (System.currentTimeMillis() / 1000).toString()
        val nonce = Base64.encodeToString(
            ByteArray(6).also { SecureRandom().nextBytes(it) },
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
        )
        val path = url.encodedPath + (url.encodedQuery?.let { "?$it" } ?: "")
        val payloadHash = MessageDigest.getInstance("SHA-256").run {
            update("hawk.1.payload\napplication/json\n".toByteArray(Charsets.UTF_8))
            update(body)
            update("\n".toByteArray(Charsets.UTF_8))
            Base64.encodeToString(digest(), Base64.NO_WRAP)
        }
        val normalized = "hawk.1.header\n$timestamp\n$nonce\n${method.uppercase()}\n$path\n${url.host}\n${url.port}\n$payloadHash\n\n"
        val mac = Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(hmacKey, "HmacSHA256"))
        }.doFinal(normalized.toByteArray(Charsets.UTF_8))
        val macB64 = Base64.encodeToString(mac, Base64.NO_WRAP)
        return "Hawk id=\"$tokenId\", ts=\"$timestamp\", nonce=\"$nonce\", mac=\"$macB64\", hash=\"$payloadHash\""
    }

    private fun pbkdf2HmacSha256(password: ByteArray, salt: ByteArray, iterations: Int, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(password, "HmacSHA256")) }
        val output = ByteArray(length)
        var offset = 0
        var block = 1
        while (offset < length) {
            val first = mac.doFinal(salt + ByteBuffer.allocate(4).putInt(block).array())
            var u = first
            val result = first.copyOf()
            repeat(iterations - 1) {
                u = mac.doFinal(u)
                for (i in result.indices) result[i] = (result[i].toInt() xor u[i].toInt()).toByte()
            }
            val count = minOf(result.size, length - offset)
            System.arraycopy(result, 0, output, offset, count)
            offset += count
            block++
        }
        return output
    }

    private fun hkdf(ikm: ByteArray, info: String, length: Int): ByteArray {
        val extract = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
            doFinal(ikm)
        }
        val infoBytes = info.toByteArray(Charsets.UTF_8)
        val output = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            val mac = Mac.getInstance("HmacSHA256").apply {
                init(SecretKeySpec(extract, "HmacSHA256"))
            }
            val block = mac.doFinal(previous + infoBytes + byteArrayOf(counter.toByte()))
            val count = minOf(block.size, length - offset)
            System.arraycopy(block, 0, output, offset, count)
            offset += count
            previous = block
            counter++
        }
        return output
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun String.hexToBytes(): ByteArray {
        require(length % 2 == 0) { "Invalid token encoding" }
        return ByteArray(length / 2) { index ->
            substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun String.toHttpUrlOrThrow(): HttpUrl = try {
        HttpUrl.get(this)
    } catch (e: IllegalArgumentException) {
        throw AuthException("Invalid Firefox Accounts URL.")
    }

    private fun normalizeEmail(value: String): String =
        value.replace(Regex("[\\p{Z}\\u200B-\\u200D\\uFEFF\\u00A0\\s]+"), "").trim().lowercase()

    companion object {
        private const val FXA_API = "https://api.accounts.firefox.com/v1"
        private const val CLIENT_ID = "5882386c6d801776"
        private const val OAUTH_SCOPE = "profile https://identity.mozilla.com/apps/vpn"
        private const val PROTOCOL_VERSION = "identity.mozilla.com/picl/v1/"
        private const val DEFAULT_TOKEN_TTL = 86400L
        private const val USER_AGENT = "MozillaVPN/2.35.0 (sys:linux; iap:true)"
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
    }
}
