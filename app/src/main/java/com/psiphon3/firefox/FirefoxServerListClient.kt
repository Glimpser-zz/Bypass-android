package com.psiphon3.firefox

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import org.json.JSONObject
import java.io.IOException

data class FirefoxServerCandidate(
    val host: String,
    val port: Int,
    val countryCode: String,
    val countryName: String,
    val cityCode: String,
    val cityName: String,
)

class FirefoxServerListClient(
    private val client: okhttp3.OkHttpClient = FirefoxControlPlaneHttp.client,
) {
    suspend fun fetchCandidates(): List<FirefoxServerCandidate> = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(REMOTE_SETTINGS_URL)
            .header("Accept", "application/json")
            .header("User-Agent", USER_AGENT)
            .build()

        client.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw IOException("Mozilla VPN server list failed (HTTP ${response.code})")
            }
            val records = JSONObject(body).optJSONArray("data") ?: return@withContext emptyList()
            val candidates = mutableListOf<FirefoxServerCandidate>()
            for (i in 0 until records.length()) {
                val record = records.optJSONObject(i) ?: continue
                val country = record.optJSONObject("country") ?: record
                val countryName = country.optString("name")
                val countryCode = country.optString("code")
                if (countryCode.isBlank() || countryName.equals("CatchAll Anycast", true)) continue
                val cities = country.optJSONArray("cities") ?: continue
                for (ci in 0 until cities.length()) {
                    val city = cities.optJSONObject(ci) ?: continue
                    val servers = city.optJSONArray("servers") ?: continue
                    for (si in 0 until servers.length()) {
                        val server = servers.optJSONObject(si) ?: continue
                        if (server.optBoolean("quarantined", false)) continue
                        val serverHost = server.optString("hostname")
                        val serverPort = server.optInt("port", 0)
                        val protocols = server.optJSONArray("protocols")
                        var host = ""
                        var port = 0
                        if (protocols != null && protocols.length() > 0) {
                            for (pi in 0 until protocols.length()) {
                                val protocol = protocols.optJSONObject(pi) ?: continue
                                if (protocol.optString("name") != "connect") continue
                                host = protocol.optString("host").ifBlank { serverHost }
                                port = protocol.optInt("port", 0).takeIf { it > 0 } ?: serverPort
                                break
                            }
                        } else {
                            host = serverHost
                            port = serverPort
                        }
                        // Some Remote Settings records list protocols without a CONNECT
                        // entry. In that case, retain the record's documented host/port.
                        if (host.isBlank()) host = serverHost
                        if (port !in 1..65535) port = serverPort
                        if (host.isNotBlank() && port in 1..65535) {
                            candidates.add(
                                FirefoxServerCandidate(
                                    host = host,
                                    port = port,
                                    countryCode = countryCode,
                                    countryName = countryName,
                                    cityCode = city.optString("code"),
                                    cityName = city.optString("name"),
                                ),
                            )
                        }
                    }
                }
            }
            if (candidates.isEmpty()) throw IOException("Mozilla VPN server list contained no usable CONNECT endpoints")
            candidates
        }
    }

    companion object {
        private const val REMOTE_SETTINGS_URL =
            "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"
        private const val USER_AGENT = "MozillaVPN/2.35.0 (sys:linux; iap:true)"
    }
}
