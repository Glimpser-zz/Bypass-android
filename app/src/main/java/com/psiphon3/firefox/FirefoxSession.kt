/*
 * Copyright (C) 2026 Glimpser
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package com.psiphon3.firefox

data class FirefoxSession(
    val accessToken: String,
    val refreshToken: String?,
    val expiresAtEpochSeconds: Long,
)
