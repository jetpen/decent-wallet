package org.decentwallet.wallet.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test

class WalletLoginChallengeTest {
    private val challenge = "A".repeat(43)
    private val valid = """{"profile":"decent-wallet-login-v1","challenge":"$challenge","csrf_token":"browser-only"}"""

    @Test fun parsesExactChallengeAndAnchorsItsFiveMinuteLifetimeAtGetTime() {
        val parsed = WalletLoginChallenge.parse(valid.toByteArray(), receivedAtEpochSeconds = 1_800_000_000L)
        assertEquals("decent-wallet-login-v1", parsed.profile)
        assertEquals(challenge, parsed.challenge)
        assertEquals(1_800_000_300L, parsed.expiresAtEpochSeconds)
        assertFalse(parsed.isExpiredAt(1_800_000_299L))
    }

    @Test fun rejectsDuplicateUnknownMissingMalformedAndWrongTypedChallengeFields() {
        val bad = listOf(
            valid.replace("decent-wallet-login-v1", "other"),
            valid.replace(challenge, "short"),
            valid.replace("\"csrf_token\":\"browser-only\"", "\"csrf_token\":\"browser-only\",\"x\":\"y\""),
            valid.replace(",\"csrf_token\":\"browser-only\"", ""),
            valid.replace("\"csrf_token\":\"browser-only\"", "\"csrf_token\":null"),
            valid.replace("\"csrf_token\":\"browser-only\"", "\"csrf_token\":\"browser-only\",\"profile\":\"decent-wallet-login-v1\""),
            "[]", "{}", """{"profile":"decent-wallet-login-v1","challenge":"$challenge","csrf_token":"x","x":1}""",
        )
        bad.forEach { json ->
            try { WalletLoginChallenge.parse(json.toByteArray()); fail("accepted malformed challenge response") }
            catch (_: IllegalArgumentException) { }
        }
    }

    @Test fun rejectsExpiryOverflow() {
        try { WalletLoginChallenge.parse(valid.toByteArray(), Long.MAX_VALUE); fail("overflowed expiry") }
        catch (_: IllegalArgumentException) { }
    }
}
