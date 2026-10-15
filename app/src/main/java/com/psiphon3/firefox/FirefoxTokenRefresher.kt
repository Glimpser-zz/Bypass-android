/*
 * Copyright (C) 2026 Glimpser
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Refreshes an already-authorized Firefox Account session. This does not implement
 * password sign-in or 2FA; those require the FxA Hawk authentication protocol.
 */
package com.psiphon3.firefox

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException

class FirefoxTokenRefresher(
    private val store: FirefoxSessionStore,
    private val client: okhttp3.OkHttpClient = FirefoxControlPlaneHttp.client,
) {
    class RefreshException(message: String, val permanent: Boolean = false) : IOException(message)

    suspend fun refresh(force: Boolean = false): FirefoxSession = withContext(Dispatchers.IO) {
        val current = store.load() ?: throw RefreshException("Firefox account is not signed in", true)
        val now = System.currentTimeMillis() / 1000
        if (!force && current.expiresAtEpochSeconds > now + 60) return@withContext current
        val refreshToken = current.refreshToken
            ?: throw RefreshException("Firefox session has no refresh token; sign in again", true)

        val body = JSONObject()
            .put("client_id", FIREFOX_CLIENT_ID)
            .put("grant_type", "refresh_token")
            .put("refresh_token", refreshToken)
            .put("scope", OAUTH_SCOPE)
            .toString()
            .toRequestBody("application/json; charset=utf-8".toMediaType())

        val request = Request.Builder()
            .url("https://oauth.accounts.firefox.com/v1/token")
            .header("User-Agent", "MozillaVPN/2.35.0 (sys:linux; iap:true)")
            .header("Accept", "application/json")
            .post(body)
            .build()

        client.newCall(request).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                val permanent = response.code == 400 || response.code == 401 || response.code == 403
                throw RefreshException("Firefox token refresh failed (HTTP ${response.code})", permanent)
            }
            val json = JSONObject(text)
            val access = json.optString("access_token").takeIf { it.isNotBlank() }
                ?: throw RefreshException("Firefox response did not contain an access token")
            val renewedRefresh = json.optString("refresh_token").takeIf { it.isNotBlank() } ?: refreshToken
            val expiresIn = json.optLong("expires_in", 86400L).coerceAtLeast(60L)
            val updated = FirefoxSession(access, renewedRefresh, now + expiresIn)
            store.save(updated)
            updated
        }
    }

    companion object {
        private const val FIREFOX_CLIENT_ID = "5882386c6d801776"
        private const val OAUTH_SCOPE = "profile https://identity.mozilla.com/apps/vpn"
    }
}
