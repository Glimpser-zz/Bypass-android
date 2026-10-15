/*
 * Copyright (C) 2026 Glimpser
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Control-plane preflight for the future Firefox transport. This deliberately does
 * not claim that a tunnel is connected: a proxy pass is only one input to the data plane.
 */
package com.psiphon3.firefox

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class FirefoxConnectionPreflight(
    private val sessionStore: FirefoxSessionStore,
    private val tokenRefresher: FirefoxTokenRefresher,
    private val guardian: GuardianControlPlane = GuardianControlPlane(),
) {
    sealed class Result {
        data class Ready(
            val accountStatus: GuardianControlPlane.AccountStatus,
            val proxyPass: GuardianControlPlane.ProxyPass,
        ) : Result()

        data object SignInRequired : Result()
        data class ChallengeRequired(val message: String) : Result()
        data class Failed(val message: String, val retryable: Boolean) : Result()
    }

    suspend fun check(): Result = withContext(Dispatchers.IO) {
        val existing = sessionStore.load() ?: return@withContext Result.SignInRequired
        val session = try {
            if (existing.expiresAtEpochSeconds <= System.currentTimeMillis() / 1000 + 60) {
                tokenRefresher.refresh(force = true)
            } else {
                existing
            }
        } catch (e: FirefoxTokenRefresher.RefreshException) {
            if (e.permanent) {
                sessionStore.clear()
                return@withContext Result.SignInRequired
            }
            return@withContext Result.Failed(e.message ?: "Firefox session refresh failed", true)
        } catch (e: Exception) {
            return@withContext Result.Failed("Firefox session refresh failed", true)
        }

        try {
            val status = guardian.fetchAccountStatus(session.accessToken)
            if (!status.subscribed) {
                return@withContext Result.Failed("Firefox VPN account is not subscribed", false)
            }
            val pass = guardian.fetchProxyPass(session.accessToken)
            Result.Ready(status, pass)
        } catch (e: GuardianControlPlane.GuardianException) {
            if (e.challengeRequired) {
                Result.ChallengeRequired(e.message ?: "Guardian challenge required")
            } else if (e.statusCode == 401 || e.statusCode == 403) {
                sessionStore.clear()
                Result.SignInRequired
            } else {
                Result.Failed(e.message ?: "Guardian request failed", e.statusCode == null || e.statusCode!! >= 500 || e.statusCode == 429)
            }
        } catch (e: Exception) {
            Result.Failed("Could not contact Firefox Guardian", true)
        }
    }
}
