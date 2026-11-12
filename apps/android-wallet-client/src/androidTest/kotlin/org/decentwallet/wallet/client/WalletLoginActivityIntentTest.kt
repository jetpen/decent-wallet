package org.decentwallet.wallet.client

import android.content.Intent
import android.net.Uri
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class WalletLoginActivityIntentTest {
    @Test fun invalidIntentIsRejectedAtTheActivityBoundary() {
        val scenario = launch("http://login.example.invalid/realms/demo/decent-wallet-login/v1/transactions/${"A".repeat(43)}")
        scenario.use {
            it.onActivity { activity ->
                val matches = ArrayList<View>()
                activity.window.decorView.findViewsWithText(matches, "invalid or not trusted", View.FIND_VIEWS_WITH_TEXT)
                assertTrue("invalid app-link URL was not rejected visibly", matches.any { it is TextView })
            }
        }
    }

    @Test fun missingUnlockedHostSessionFailsBeforeNetworkOrProof() {
        val link = "${BuildConfig.WALLET_LOGIN_ORIGIN}/realms/demo/decent-wallet-login/v1/transactions/${"A".repeat(43)}"
        val scenario = launch(link)
        scenario.use {
            it.onActivity { activity ->
                val matches = ArrayList<View>()
                activity.window.decorView.findViewsWithText(matches, "already-unlocked wallet is required", View.FIND_VIEWS_WITH_TEXT)
                assertTrue("missing wallet host did not fail closed", matches.any { it is TextView })
            }
        }
    }

    private fun launch(url: String): ActivityScenario<WalletLoginActivity> {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            .setClass(context, WalletLoginActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return ActivityScenario.launch(intent)
    }
}
