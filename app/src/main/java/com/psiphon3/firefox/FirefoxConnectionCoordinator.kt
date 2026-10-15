package com.psiphon3.firefox

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * Runs the control-plane preflight, discovers current Mozilla endpoints, then opens
 * the first reachable HTTP/2 upstream session. This establishes only the upstream
 * transport; it does not yet route Android TUN packets into CONNECT streams.
 */
class FirefoxConnectionCoordinator(
    private val preflight: FirefoxConnectionPreflight,
    private val serverList: FirefoxServerListClient = FirefoxServerListClient(),
    private val factory: FirefoxTransportSessionFactory = FirefoxTransportSessionFactory(),
) {
    sealed class Result {
        data class Connected(
            val candidate: FirefoxServerCandidate,
            val session: UpstreamSession,
        ) : Result()

        data class SocksReady(
            val candidate: FirefoxServerCandidate,
            val session: UpstreamSession,
            val socksServer: FirefoxH2Socks5Server,
            val socksPort: Int,
        ) : Result()

        data object SignInRequired : Result()
        data class ChallengeRequired(val message: String) : Result()
        data class Failed(val message: String, val retryable: Boolean) : Result()
    }

    suspend fun connect(countryCode: String? = null): Result = withContext(Dispatchers.IO) {
        val ready = when (val check = preflight.check()) {
            is FirefoxConnectionPreflight.Result.Ready -> check
            FirefoxConnectionPreflight.Result.SignInRequired -> return@withContext Result.SignInRequired
            is FirefoxConnectionPreflight.Result.ChallengeRequired ->
                return@withContext Result.ChallengeRequired(check.message)
            is FirefoxConnectionPreflight.Result.Failed ->
                return@withContext Result.Failed(check.message, check.retryable)
        }

        val candidates = try {
            serverList.fetchCandidates().let { all ->
                if (countryCode.isNullOrBlank() || countryCode.equals("ANY", true)) all
                else all.filter { it.countryCode.equals(countryCode, true) }
            }
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (e: Exception) {
            return@withContext Result.Failed(e.message ?: "Could not fetch Mozilla VPN server list", true)
        }

        if (candidates.isEmpty()) {
            return@withContext Result.Failed(
                if (countryCode.isNullOrBlank() || countryCode.equals("ANY", true))
                    "Mozilla VPN server list contains no usable endpoints"
                else "No Mozilla VPN endpoints found for country $countryCode",
                true,
            )
        }

        // Avoid serially waiting on every endpoint in a large country list.
        // The caller can retry to get a different randomized sample.
        val attempts = candidates.shuffled().take(MAX_ENDPOINT_ATTEMPTS)
        var lastFailure: Exception? = null
        for (candidate in attempts) {
            try {
                val session = factory.connect(candidate, ready.proxyPass)
                return@withContext Result.Connected(candidate, session)
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (e: Exception) {
                lastFailure = e
            }
        }

        Result.Failed(
            "Could not establish HTTP/2 to any of ${attempts.size} attempted Mozilla VPN endpoints" +
                (lastFailure?.message?.let { ": $it" } ?: ""),
            true,
        )
    }


    /**
     * Opens the upstream and starts its loopback SOCKS5 adapter.
     * The caller owns SocksReady.socksServer and must close it on every stop/revoke path.
     * This method does not establish the Android VPN interface or route TUN traffic.
     */
    suspend fun connectWithSocks5(countryCode: String? = null): Result {
        return when (val result = connect(countryCode)) {
            is Result.Connected -> {
                val socks = FirefoxH2Socks5Server(result.session)
                try {
                    val port = socks.start()
                    Result.SocksReady(result.candidate, result.session, socks, port)
                } catch (e: Exception) {
                    socks.close()
                    result.session.close()
                    Result.Failed("Upstream connected but local SOCKS5 listener could not start: ${e.message}", true)
                }
            }
            else -> result
        }
    }

    private companion object {
        const val MAX_ENDPOINT_ATTEMPTS = 4
    }
}
