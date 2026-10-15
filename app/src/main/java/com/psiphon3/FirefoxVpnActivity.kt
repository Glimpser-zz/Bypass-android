package com.psiphon3

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.psiphon3.firefox.FirefoxAuthRepository
import com.psiphon3.firefox.FirefoxSessionStore
import com.psiphon3.firefox.FirefoxTransportSettingsStore
import com.psiphon3.psiphonlibrary.TunnelManager
import com.psiphon3.psiphonlibrary.TunnelVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import net.grandcentrix.tray.AppPreferences

/** Experimental Firefox HTTP/2 transport settings and account sign-in. */
class FirefoxVpnActivity : AppCompatActivity() {
    private val uiScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var auth: FirefoxAuthRepository
    private lateinit var email: EditText
    private lateinit var edgeAddress: EditText
    private lateinit var transportSettings: FirefoxTransportSettingsStore
    private lateinit var password: EditText
    private lateinit var code: EditText
    private lateinit var signInButton: Button
    private lateinit var verifyButton: Button
    private lateinit var connectButton: Button
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "Firefox VPN (experimental)"
        auth = FirefoxAuthRepository(FirefoxSessionStore(applicationContext))
        transportSettings = FirefoxTransportSettingsStore(applicationContext)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(24))
        }
        val scroll = ScrollView(this).apply { addView(content) }

        content.addView(TextView(this).apply {
            text = "Firefox HTTP/2 transport"
            textSize = 22f
            setTypeface(typeface, Typeface.BOLD)
        }, matchWidth())
        content.addView(TextView(this).apply {
            text = "Experimental TCP-only mode. DNS queries are carried as TCP through the upstream; other UDP traffic is not supported. This is separate from the default Psiphon mode."
            textSize = 14f
            setPadding(0, dp(8), 0, dp(16))
        }, matchWidth())

        edgeAddress = EditText(this).apply {
            hint = "Optional CDN edge IPv4 / hostname"
            inputType = InputType.TYPE_CLASS_TEXT
            setSingleLine(true)
            setText(transportSettings.loadEdgeAddress().orEmpty())
        }
        content.addView(edgeAddress, matchWidth())
        val saveEdgeButton = Button(this).apply { text = "Save edge address" }
        content.addView(saveEdgeButton, matchWidth())

        val savedCredentials = runCatching { authCredentialsStore().loadCredentials() }.getOrNull()
        email = EditText(this).apply {
            hint = "Firefox Account email"
            setText(savedCredentials?.first.orEmpty())
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            setSingleLine(true)
        }
        password = EditText(this).apply {
            hint = "Firefox Account password"
            setText(savedCredentials?.second.orEmpty())
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
        }
        code = EditText(this).apply {
            hint = "Email verification code"
            inputType = InputType.TYPE_CLASS_TEXT
            setSingleLine(true)
            visibility = View.GONE
        }
        content.addView(email, matchWidth())
        content.addView(password, matchWidth())

        signInButton = Button(this).apply { text = "Sign in" }
        verifyButton = Button(this).apply {
            text = "Verify code"
            visibility = View.GONE
        }
        connectButton = Button(this).apply { text = "Connect using Firefox" }
        val signOutButton = Button(this).apply { text = "Sign out" }
        status = TextView(this).apply {
            textSize = 14f
            setPadding(0, dp(12), 0, 0)
        }

        content.addView(signInButton, matchWidth())
        content.addView(code, matchWidth())
        content.addView(verifyButton, matchWidth())
        content.addView(connectButton, matchWidth())
        content.addView(signOutButton, matchWidth())
        content.addView(status, matchWidth())
        setContentView(scroll)

        saveEdgeButton.setOnClickListener {
            try {
                transportSettings.saveEdgeAddress(edgeAddress.text?.toString().orEmpty())
                status.text = if (transportSettings.loadEdgeAddress() == null) {
                    "Edge address cleared; using the Mozilla endpoint address."
                } else {
                    "Edge saved. TLS SNI remains the Mozilla endpoint hostname; the chosen edge must serve that hostname."
                }
            } catch (e: IllegalArgumentException) {
                status.text = e.message ?: "Invalid edge address."
            }
        }
        signInButton.setOnClickListener { beginSignIn() }
        verifyButton.setOnClickListener { verifyCode() }
        connectButton.setOnClickListener { requestVpnPermission() }
        signOutButton.setOnClickListener {
            auth.signOut()
            authCredentialsStore().clearCredentials()
            email.text?.clear()
            password.text?.clear()
            code.text?.clear()
            code.visibility = View.GONE
            verifyButton.visibility = View.GONE
            connectButton.isEnabled = false
            status.text = "Signed out."
        }

        val signedIn = runCatching { auth.isSignedIn() }.getOrDefault(false)
        connectButton.isEnabled = signedIn
        status.text = if (signedIn) {
            "A saved Firefox Account session is available."
        } else {
            "Sign in to a Firefox Account with an active VPN subscription."
        }
    }

    private fun beginSignIn() {
        val emailValue = email.text?.toString().orEmpty()
        val passwordValue = password.text?.toString().orEmpty()
        // EncryptedSharedPreferences is used by FirefoxSessionStore for credentials.
        runCatching { authCredentialsStore().saveCredentials(emailValue, passwordValue) }
        signInButton.isEnabled = false
        status.text = "Signing in…"
        uiScope.launch {
            try {
                when (auth.beginLogin(emailValue, passwordValue)) {
                    FirefoxAuthRepository.LoginResult.SignedIn -> {
                        code.visibility = View.GONE
                        verifyButton.visibility = View.GONE
                        connectButton.isEnabled = true
                        status.text = "Signed in. Credentials are saved encrypted on this device."
                    }
                    FirefoxAuthRepository.LoginResult.NeedsEmailCode -> {
                        code.visibility = View.VISIBLE
                        verifyButton.visibility = View.VISIBLE
                        status.text = "Enter the verification code sent by Firefox Accounts."
                    }
                }
            } catch (e: Exception) {
                status.text = e.message ?: "Firefox Account sign-in failed."
                connectButton.isEnabled = runCatching { auth.isSignedIn() }.getOrDefault(false)
            } finally {
                signInButton.isEnabled = true
            }
        }
    }

    private fun verifyCode() {
        verifyButton.isEnabled = false
        status.text = "Verifying…"
        uiScope.launch {
            try {
                auth.verifyEmailCode(code.text?.toString().orEmpty())
                code.visibility = View.GONE
                verifyButton.visibility = View.GONE
                connectButton.isEnabled = true
                status.text = "Signed in. Credentials are saved encrypted on this device."
            } catch (e: Exception) {
                status.text = e.message ?: "Verification failed."
            } finally {
                verifyButton.isEnabled = true
            }
        }
    }

    private fun requestVpnPermission() {
        if (!runCatching { auth.isSignedIn() }.getOrDefault(false)) {
            status.text = "Sign in before connecting."
            return
        }
        val prefs = AppPreferences(applicationContext)
        if (prefs.getBoolean(getString(R.string.serviceRunningPreference), false)) {
            status.text = "Stop the current Psiphon tunnel on the main screen, then try again."
            return
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(prepare, REQUEST_VPN_PERMISSION)
        } else {
            startFirefoxService()
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_PERMISSION) {
            if (resultCode == Activity.RESULT_OK) {
                startFirefoxService()
            } else {
                status.text = "VPN permission was not granted."
            }
        }
    }

    private fun startFirefoxService() {
        val intent = Intent(this, TunnelVpnService::class.java)
            .setAction(TunnelManager.INTENT_ACTION_START_FIREFOX_TUNNEL)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ContextCompat.startForegroundService(this, intent)
        } else {
            startService(intent)
        }
        status.text = "Starting Firefox transport…"
    }

    private fun authCredentialsStore(): FirefoxSessionStore = FirefoxSessionStore(applicationContext)

    private fun matchWidth(): LinearLayout.LayoutParams =
        LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    override fun onDestroy() {
        uiScope.cancel()
        super.onDestroy()
    }

    private companion object {
        const val REQUEST_VPN_PERMISSION = 7402
    }
}
