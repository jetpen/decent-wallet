package org.decentwallet.wallet.client

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class WalletLoginTransactionUrlTest {
    private val origin = "https://login.example.test"
    private val handle = "A".repeat(43)
    private val route = "/realms/demo/decent-wallet-login/v1/transactions/$handle"

    @Test fun acceptsOnlyTheConfiguredHttpsOriginAndExactTransactionRoute() {
        val parsed = WalletLoginTransactionUrl.parse(origin + route, origin)
        assertEquals(origin, parsed.origin)
        assertEquals(route, parsed.path)
        assertEquals("demo", parsed.realm)
        assertEquals(handle, parsed.handle)
        assertEquals(origin + route, parsed.url)
    }

    @Test fun rejectsUnsafeAndAmbiguousIntentUrls() {
        val bad = listOf(
            "http://login.example.test$route", "https://evil.example.test$route",
            "https://user@login.example.test$route", "$origin$route#fragment", "$origin$route?x=1",
            "$origin/realms/demo/decent-wallet-login/v1/transactions/short",
            "$origin/other/demo/decent-wallet-login/v1/transactions/$handle",
            "$origin/realms/%64emo/decent-wallet-login/v1/transactions/$handle",
            "$origin$route/extra", "$origin$route%2fother", "https://login.example.test:0$route",
        )
        bad.forEach { raw ->
            try { WalletLoginTransactionUrl.parse(raw, origin); fail("accepted unsafe URL") }
            catch (_: IllegalArgumentException) { }
        }
    }

    @Test fun rejectsNonOriginConfiguration() {
        listOf("http://login.example.test", "https://login.example.test/", "https://login.example.test:0", "https://user@login.example.test", "https://login.example.test/path")
            .forEach { configured ->
                try { WalletLoginTransactionUrl.parse(origin + route, configured); fail("accepted non-origin config") }
                catch (_: IllegalArgumentException) { }
            }
    }
}
