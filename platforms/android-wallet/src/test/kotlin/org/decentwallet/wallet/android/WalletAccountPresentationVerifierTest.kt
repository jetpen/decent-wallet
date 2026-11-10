package org.decentwallet.wallet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.math.BigInteger

class WalletAccountPresentationVerifierTest {
    @Test
    fun convertsOnlyValuesWithinSignedLongRange() {
        assertEquals(Long.MIN_VALUE, WalletAccountPresentationVerifier.exactLong(BigInteger.valueOf(Long.MIN_VALUE)))
        assertEquals(Long.MAX_VALUE, WalletAccountPresentationVerifier.exactLong(BigInteger.valueOf(Long.MAX_VALUE)))
        assertThrows(WalletDisclosureRequestException::class.java) {
            WalletAccountPresentationVerifier.exactLong(BigInteger.valueOf(Long.MIN_VALUE).subtract(BigInteger.ONE))
        }
        assertThrows(WalletDisclosureRequestException::class.java) {
            WalletAccountPresentationVerifier.exactLong(BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE))
        }
    }
}
