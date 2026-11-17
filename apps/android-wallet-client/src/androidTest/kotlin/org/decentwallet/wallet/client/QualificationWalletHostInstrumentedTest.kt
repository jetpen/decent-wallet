package org.decentwallet.wallet.client

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class QualificationWalletHostInstrumentedTest {
    @Test fun qualificationAppLinkResolvesToSetupAndIsNotForwardedBeforeUnlock() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        assumeTrue("qualification-only assertions", context.packageName.endsWith(".qualification"))
        val host = Uri.parse(BuildConfig.WALLET_LOGIN_ORIGIN).host
        val uri = Uri.parse("https://$host/realms/demo/decent-wallet-login/v1/transactions/${"A".repeat(43)}")
        val implicit = Intent(Intent.ACTION_VIEW, uri).setPackage(context.packageName)
        val resolved = context.packageManager.resolveActivity(implicit, PackageManager.MATCH_DEFAULT_ONLY)
        assertEquals("org.decentwallet.wallet.client.QualificationWalletSetupActivity", resolved?.activityInfo?.name)

        val app = context.applicationContext
        val acquireIdentity = app.javaClass.getMethod("acquireWalletLoginIdentity", Activity::class.java)
        val nativeTrust = app.javaClass.getMethod("nativeDisclosureTrust", Activity::class.java)
        val explicit = Intent(Intent.ACTION_VIEW, uri)
            .setClassName(context.packageName, "org.decentwallet.wallet.client.QualificationWalletSetupActivity")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val monitor = instrumentation.addMonitor("org.decentwallet.wallet.client.WalletLoginActivity", null, false)
        val activity = instrumentation.startActivitySync(explicit)
        try {
            assertTrue("setup Activity must remain visible before wallet unlock", !activity.isFinishing)
            assertNull("fresh qualification host unexpectedly contains wallet identity", acquireIdentity.invoke(app, activity))
            assertNull("offline qualification host unexpectedly has static native trust", nativeTrust.invoke(app, activity))
            assertFalse("incoming App Link was forwarded before wallet unlock", instrumentation.checkMonitorHit(monitor, 0))
            val forward = activity.javaClass.getDeclaredMethod("walletLoginIntent", Uri::class.java).apply { isAccessible = true }
            val retained = forward.invoke(activity, uri) as Intent
            assertEquals(uri, retained.data)
            assertEquals("org.decentwallet.wallet.client.WalletLoginActivity", retained.component?.className)
            assertEquals(Intent.ACTION_VIEW, retained.action)
            val labels = ArrayList<View>()
            activity.window.decorView.findViewsWithText(labels, "Native account disclosure will remain unavailable", View.FIND_VIEWS_WITH_TEXT)
            assertTrue("offline trust state is not disclosed", labels.any { it is TextView })
        } finally {
            activity.finish()
            instrumentation.removeMonitor(monitor)
        }
    }
}
