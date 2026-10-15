package com.psiphon3.firefox

import android.util.Log

internal object FirefoxLog {
    fun d(tag: String, message: String) = Log.d(tag, message)
    fun i(tag: String, message: String) = Log.i(tag, message)
    fun w(tag: String, message: String, error: Throwable? = null) {
        if (error == null) Log.w(tag, message) else Log.w(tag, message, error)
    }
    fun e(tag: String, message: String, error: Throwable? = null) {
        if (error == null) Log.e(tag, message) else Log.e(tag, message, error)
    }
}
