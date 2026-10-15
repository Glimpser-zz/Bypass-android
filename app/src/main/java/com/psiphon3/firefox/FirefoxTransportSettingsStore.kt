package com.psiphon3.firefox

import android.content.Context

/** Non-secret transport settings, read by the VPN service when a connection starts. */
class FirefoxTransportSettingsStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(
        PREFS_NAME,
        Context.MODE_PRIVATE,
    )

    fun loadEdgeAddress(): String? = preferences.getString(KEY_EDGE_ADDRESS, null)
        ?.trim()
        ?.takeIf { it.isNotEmpty() && isValidEdgeAddress(it) }

    fun saveEdgeAddress(rawValue: String) {
        val value = rawValue.trim()
        require(value.isEmpty() || isValidEdgeAddress(value)) {
            "Enter an IPv4 address or hostname only; do not include a scheme, port, or path."
        }
        preferences.edit().putString(KEY_EDGE_ADDRESS, value).apply()
    }

    private fun isValidEdgeAddress(value: String): Boolean =
        value.length <= 253 &&
            EDGE_ADDRESS_PATTERN.matches(value) &&
            !value.startsWith(".") &&
            !value.endsWith(".") &&
            !value.contains("..")

    private companion object {
        const val PREFS_NAME = "firefox_transport_settings"
        const val KEY_EDGE_ADDRESS = "edge_address"
        val EDGE_ADDRESS_PATTERN = Regex("^[A-Za-z0-9.-]+$")
    }
}
