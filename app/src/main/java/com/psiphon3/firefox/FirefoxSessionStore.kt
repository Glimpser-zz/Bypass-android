/*
 * Copyright (C) 2026 Glimpser
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Stores Firefox session credentials using AndroidX encrypted preferences.
 * Tokens are secrets: never include them in logs, UI messages, or crash reports.
 */
package com.psiphon3.firefox

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class FirefoxSessionStore(context: Context) {
    private val preferences = EncryptedSharedPreferences.create(
        context.applicationContext,
        FILE_NAME,
        MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    /**
     * Remember login fields encrypted on-device so the user does not have to retype them.
     * These are kept separate from the short-lived access/refresh token session.
     */
    @Synchronized
    fun saveCredentials(email: String, password: String) {
        preferences.edit()
            .putString(KEY_EMAIL, email)
            .putString(KEY_PASSWORD, password)
            .apply()
    }

    @Synchronized
    fun loadCredentials(): Pair<String, String>? {
        val email = preferences.getString(KEY_EMAIL, null) ?: return null
        val password = preferences.getString(KEY_PASSWORD, null) ?: return null
        if (email.isBlank() || password.isBlank()) return null
        return email to password
    }

    @Synchronized
    fun clearCredentials() {
        preferences.edit()
            .remove(KEY_EMAIL)
            .remove(KEY_PASSWORD)
            .apply()
    }

    @Synchronized
    fun save(session: FirefoxSession) {
        require(session.accessToken.isNotBlank()) { "Access token must not be blank" }
        preferences.edit()
            .putString(KEY_ACCESS, session.accessToken)
            .putString(KEY_REFRESH, session.refreshToken)
            .putLong(KEY_EXPIRY, session.expiresAtEpochSeconds)
            .apply()
    }

    @Synchronized
    fun load(): FirefoxSession? {
        val access = preferences.getString(KEY_ACCESS, null)?.takeIf { it.isNotBlank() } ?: return null
        return FirefoxSession(
            accessToken = access,
            refreshToken = preferences.getString(KEY_REFRESH, null)?.takeIf { it.isNotBlank() },
            expiresAtEpochSeconds = preferences.getLong(KEY_EXPIRY, 0L),
        )
    }

    fun hasUsableAccessToken(nowEpochSeconds: Long = System.currentTimeMillis() / 1000): Boolean {
        val session = load() ?: return false
        return session.expiresAtEpochSeconds > nowEpochSeconds + EXPIRY_SKEW_SECONDS
    }

    @Synchronized
    fun clear() {
        preferences.edit().clear().apply()
    }

    companion object {
        private const val FILE_NAME = "firefox_vpn_session"
        private const val KEY_ACCESS = "access_token"
        private const val KEY_REFRESH = "refresh_token"
        private const val KEY_EXPIRY = "expires_at"
        private const val KEY_EMAIL = "account_email"
        private const val KEY_PASSWORD = "account_password"
        private const val EXPIRY_SKEW_SECONDS = 60L
    }
}
