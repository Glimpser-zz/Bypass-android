/*
 * Copyright (C) 2026 Glimpser
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Minimal Mozilla Guardian control-plane client for the Bypass Firefox transport.
 * This class deliberately does not implement Firefox account sign-in; callers must
 * supply a short-lived access token obtained through the supported FxA flow.
 */
package com.psiphon3.firefox;

import kotlinx.coroutines.Dispatchers;
import kotlinx.coroutines.withContext;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.json.JSONObject;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Calls the public Mozilla Guardian API to validate an account and obtain a proxy pass.
 *
 * A 406 response is surfaced explicitly because Guardian may require a Fastly challenge.
 * The caller must solve that challenge using the supported flow before retrying; this
 * client intentionally does not bypass or fake the challenge.
 */
class GuardianControlPlane(
    private val endpoint: String = DEFAULT_ENDPOINT,
    private val client: OkHttpClient = defaultClient(),
) {
    data class ProxyPass(
        val token: String,
        val expiresAtEpochSeconds: Long?,
        val quotaMax: Long?,
        val quotaRemaining: Long?,
        val quotaReset: Long?,
    )

    data class AccountStatus(
        val subscribed: Boolean,
        val uid: String,
        val limitedBandwidth: Boolean,
        val maxBytes: Long?,
    )

    class GuardianException(
        message: String,
        val statusCode: Int? = null,
        val challengeRequired: Boolean = false,
    ) : IOException(message)

    suspend fun fetchProxyPass(accessToken: String): ProxyPass = withContext(Dispatchers.IO) {
        require(accessToken.isNotBlank()) { "Firefox access token is required" }
        val response = execute("GET", "/api/v1/fpn/token", accessToken)
        response.use {
            val body = it.body?.string().orEmpty()
            if (it.code == 401 || it.code == 403) {
                throw GuardianException("Guardian rejected the Firefox access token", it.code)
            }
            if (it.code == 406) {
                throw GuardianException("Guardian requires a Fastly challenge before issuing a proxy pass", 406, true)
            }
            if (it.code == 429) throw GuardianException("Guardian proxy quota is exhausted", 429)
            if (it.code != 200) {
                throw GuardianException("Guardian proxy-pass request failed (HTTP ${it.code}): ${body.take(512)}", it.code)
            }
            val json = JSONObject(body)
            val token = json.optString("token", "")
            if (token.isBlank()) throw GuardianException("Guardian response did not include a proxy token")
            ProxyPass(
                token = token,
                expiresAtEpochSeconds = json.optLong("expires_at", 0L).takeIf { value -> value > 0L }
                    ?: jwtExpiry(token),
                quotaMax = it.header("X-Quota-Limit")?.toLongOrNull(),
                quotaRemaining = it.header("X-Quota-Remaining")?.toLongOrNull(),
                quotaReset = it.header("X-Quota-Reset")?.toLongOrNull(),
            )
        }
    }

    suspend fun fetchAccountStatus(accessToken: String): AccountStatus = withContext(Dispatchers.IO) {
        require(accessToken.isNotBlank()) { "Firefox access token is required" }
        val response = execute("GET", "/api/v1/fpn/status", accessToken)
        response.use {
            val body = it.body?.string().orEmpty()
            if (it.code == 406) {
                throw GuardianException("Guardian requires a Fastly challenge", 406, true)
            }
            if (!it.isSuccessful) {
                throw GuardianException("Guardian account-status request failed (HTTP ${it.code}): ${body.take(512)}", it.code)
            }
            val json = JSONObject(body)
            AccountStatus(
                subscribed = json.optBoolean("subscribed", false),
                uid = json.optString("uid", ""),
                limitedBandwidth = json.optBoolean("limited_bandwidth", false),
                maxBytes = if (json.has("maxBytes") && !json.isNull("maxBytes")) {
                    json.optLong("maxBytes", -1L).takeIf { value -> value >= 0L }
                } else null,
            )
        }
    }

    private fun execute(method: String, path: String, accessToken: String) =
        client.newCall(
            Request.Builder()
                .url(endpoint.trimEnd('/') + path)
                .header("Authorization", "Bearer $accessToken")
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("User-Agent", "MozillaVPN/2.35.0 (sys:linux; iap:true)")
                .apply {
                    if (method == "POST") post(RequestBody.create(null, ByteArray(0)))
                    else get()
                }
                .build(),
        ).execute()

    private fun jwtExpiry(token: String): Long? = runCatching {
        val payload = token.split('.')[1]
        val padded = payload + "=".repeat((4 - payload.length % 4) % 4)
        val decoded = android.util.Base64.decode(
            padded,
            android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP,
        )
        JSONObject(String(decoded, Charsets.UTF_8)).optLong("exp", 0L).takeIf { it > 0L }
    }.getOrNull()

    companion object {
        const val DEFAULT_ENDPOINT = "https://vpn.mozilla.org"

        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .callTimeout(30, TimeUnit.SECONDS)
            .build()
    }
}
