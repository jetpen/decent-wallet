package org.decentwallet.wallet.client

import android.app.Activity
import android.content.Intent
import android.graphics.Rect
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.provider.DocumentsContract
import android.view.InputDevice
import android.view.KeyEvent
import android.view.MotionEvent

import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import android.widget.EditText
import org.decentwallet.wallet.android.AndroidWallet
import org.decentwallet.wallet.android.WalletUnlockException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class QualificationWalletImportInstrumentedTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val testContext get() = instrumentation.context
    private val password = UUID.randomUUID().toString()
    private val appLink = Uri.parse("${BuildConfig.WALLET_LOGIN_ORIGIN}/not-a-wallet-login")
    private var setup: Activity? = null

    @After fun tearDown() {
        for (attempt in 0 until 3) {
            if (!documentsUiIsActive()) break
            injectBack()
            SystemClock.sleep(200)
        }
        val activities = mutableSetOf<Activity>()
        runOnMain {
            for (stage in listOf(Stage.CREATED, Stage.STARTED, Stage.RESUMED, Stage.PAUSED, Stage.STOPPED)) {
                activities += ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(stage)
                    .filter { it is QualificationWalletSetupActivity || it is WalletLoginActivity }
            }
            setup?.let { activities += it }
            activities.forEach { if (!it.isFinishing) it.finish() }
        }
        setup = null
        testContext.contentResolver.call(
            Uri.parse("content://$FIXTURE_AUTHORITY"), "clear", null, null
        )
        (context.applicationContext as QualificationWalletHostApplication).lockWalletSession()
    }

    @Test fun unlockImportsFreshContainerAndForwardsOriginalAppLinkWithExactIdentity() {
        assumeQualificationVariant()
        val identity = "test:qualification-import-${UUID.randomUUID()}"
        withSyntheticContainer { source ->
            val application = context.applicationContext as QualificationWalletHostApplication
            val monitor = instrumentation.addMonitor(WalletLoginActivity::class.java.name, null, false)
            try {
                val activity = launchSetup()
                selectContainer(activity, source)
                enter(activity, identity, password)
                clickUnlock(activity)
                waitUntil("wallet login forwarding") { monitor.hits > 0 }
                waitUntil("setup Activity finishing after wallet login launch") {
                    var finishing = false
                    runOnMain { finishing = activity.isFinishing }
                    finishing
                }
                assertTrue("successful import did not leave setup for wallet login", activity.isFinishing)
                val installed = application.acquireWalletLoginIdentity(activity)
                assertNotNull("import did not install an unlocked wallet", installed)
                assertEquals("Identity ID was changed during import", identity, installed!!.identityId)
                assertTrue("imported wallet is locked", installed.session.isUnlocked)
                val forwarded = requireNotNull(monitor.waitForActivityWithTimeout(TimeUnit.SECONDS.toMillis(5)))
                assertEquals("incoming App Link changed", appLink, forwarded.intent.data)
                assertEquals(Intent.ACTION_VIEW, forwarded.intent.action)
                assertEquals("org.decentwallet.wallet.client.WalletLoginActivity", forwarded.componentName.className)
                waitUntil("invalid App Link rejection") {
                    var rejected = false
                    runOnMain { rejected = WalletLoginTestViews.texts(forwarded.window.decorView).any { "No proof was sent" in it } }
                    rejected
                }
                assertEquals("incoming App Link was forwarded more than once", 1, monitor.hits)
                installed.session.close()
                assertNull("locked wallet remained available to the login host", application.acquireWalletLoginIdentity(forwarded))
            } finally {
                instrumentation.removeMonitor(monitor)
            }
        }
    }

    @Test fun wrongPasswordFailsClosedWithoutForwardingOrInstallingIdentity() {
        assumeQualificationVariant()
        withSyntheticContainer { source ->
            val wrongPassword = UUID.randomUUID().toString()
            assertFalse("wrong-password fixture secret matched wallet password", wrongPassword == password)
            val directImport = File(context.cacheDir, "qualification-wrong-password-${UUID.randomUUID()}.wallet")
            val fixtureBytes = source.readBytes()
            var rejected = false
            try {
                AndroidWallet.importContainer(directImport.toPath(), fixtureBytes, wrongPassword).close()
            } catch (_: WalletUnlockException) {
                rejected = true
            } finally {
                fixtureBytes.fill(0)
                directImport.delete()
            }
            assertTrue("wallet-container API accepted an incorrect password", rejected)
            assertFalse("incorrect-password import wrote a wallet file", directImport.exists())
            val activity = launchSetup()
            selectContainer(activity, source)
            enter(activity, "test:wrong-password", wrongPassword)
            val monitor = instrumentation.addMonitor(WalletLoginActivity::class.java.name, null, false)
            try {
                clickUnlock(activity)
                waitForStatus(activity, "No proof or disclosure was sent")
                assertNull("wrong password installed a wallet identity", (context.applicationContext as QualificationWalletHostApplication)
                    .acquireWalletLoginIdentity(activity))
                assertEquals("wrong password forwarded the App Link", 0, monitor.hits)
            } finally {
                instrumentation.removeMonitor(monitor)
            }
        }
    }

    @Test fun malformedContainerFailsClosedWithoutForwardingOrInstallingIdentity() {
        assumeQualificationVariant()
        val source = File(context.cacheDir, "qualification-invalid-${UUID.randomUUID()}.bin")
        source.writeBytes("not an encrypted wallet container".toByteArray())
        installDocument(source)
        try {
            val monitor = instrumentation.addMonitor(WalletLoginActivity::class.java.name, null, false)
            try {
                val activity = launchSetup()
                selectContainer(activity, source)
                enter(activity, "test:invalid-container", password)
                clickUnlock(activity)
                waitForStatus(activity, "No proof or disclosure was sent")
                assertFalse("invalid container forwarded the App Link", monitor.hits > 0)
                assertNull("invalid container installed a wallet identity", (context.applicationContext as QualificationWalletHostApplication)
                    .acquireWalletLoginIdentity(activity))
            } finally {
                instrumentation.removeMonitor(monitor)
            }
        } finally {
            source.delete()
        }
    }

    @Test fun oversizedContainerFailsClosedWithoutForwardingOrInstallingIdentity() {
        assumeQualificationVariant()
        val source = File(context.cacheDir, "qualification-oversized-${UUID.randomUUID()}.bin")
        java.io.RandomAccessFile(source, "rw").use { it.setLength(16L * 1024 * 1024 + 1) }
        installDocument(source)
        try {
            val monitor = instrumentation.addMonitor(WalletLoginActivity::class.java.name, null, false)
            try {
                val activity = launchSetup()
                selectContainer(activity, source)
                enter(activity, "test:oversized-container", password)
                clickUnlock(activity)
                waitForStatus(activity, "No proof or disclosure was sent")
                assertFalse("oversized container forwarded the App Link", monitor.hits > 0)
                assertNull("oversized container installed a wallet identity", (context.applicationContext as QualificationWalletHostApplication)
                    .acquireWalletLoginIdentity(activity))
            } finally {
                instrumentation.removeMonitor(monitor)
            }
        } finally {
            source.delete()
        }
    }

    @Test fun documentPickerCancellationLeavesWalletLockedAndDoesNotForward() {
        assumeQualificationVariant()
        val monitor = instrumentation.addMonitor(WalletLoginActivity::class.java.name, null, false)
        try {
            val activity = launchSetup()
            openPicker(activity)
            dismissPicker(activity)
            waitUntil("picker dismissal") { isActivityResumed(activity) && !documentsUiIsActive() }
            assertFalse("cancelled document picker forwarded the App Link", monitor.hits > 0)
            assertNull("cancelled document picker installed a wallet identity", (context.applicationContext as QualificationWalletHostApplication)
                .acquireWalletLoginIdentity(activity))
            assertTrue("setup Activity should remain available after picker cancellation", !activity.isFinishing)
        } finally {
            instrumentation.removeMonitor(monitor)
        }
    }

    @Test fun recreationLocksAnAlreadyUnlockedSessionBeforeFurtherUse() {
        assumeQualificationVariant()
        withSyntheticContainer { source ->
            val application = context.applicationContext as QualificationWalletHostApplication
            val session = AndroidWallet.open(source.toPath(), password)
            application.installWalletSession("test:qualification-recreation", session)
            val walletMonitor = instrumentation.addMonitor(WalletLoginActivity::class.java.name, null, false)
            try {
                val activity = launchSetup(incoming = null)
                assertTrue("fixture session should begin unlocked", session.isUnlocked)
                runOnMain { activity.recreate() }
                var recreatedActivity: Activity? = null
                waitUntil("recreated setup Activity") {
                    runOnMain {
                        recreatedActivity = ActivityLifecycleMonitorRegistry.getInstance()
                            .getActivitiesInStage(Stage.RESUMED)
                            .firstOrNull { it is QualificationWalletSetupActivity && it !== activity }
                    }
                    recreatedActivity != null
                }
                val recreated = requireNotNull(recreatedActivity) as QualificationWalletSetupActivity
                waitForStatus(recreated, "App returned to foreground")
                assertFalse("recreation did not lock the wallet session", session.isUnlocked)
                assertNull("recreated setup retained wallet access", application.acquireWalletLoginIdentity(recreated))
                assertFalse("recreated setup forwarded without a fresh unlock", walletMonitor.hits > 0)
            } finally {
                instrumentation.removeMonitor(walletMonitor)
                application.lockWalletSession()
            }
        }
    }

    private fun assumeQualificationVariant() {
        assumeTrue("qualification-only assertions", context.packageName.endsWith(".qualification"))
    }

    private fun launchSetup(incoming: Uri? = appLink): QualificationWalletSetupActivity {
        val intent = Intent(Intent.ACTION_VIEW)
            .setClassName(context.packageName, QualificationWalletSetupActivity::class.java.name)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (incoming != null) intent.data = incoming
        instrumentation.context.startActivity(intent)
        var launched: QualificationWalletSetupActivity? = null
        waitUntil("qualification setup Activity launch") {
            runOnMain {
                launched = ActivityLifecycleMonitorRegistry.getInstance()
                    .getActivitiesInStage(Stage.RESUMED)
                    .filterIsInstance<QualificationWalletSetupActivity>()
                    .lastOrNull()
                if (launched != null) setup = launched
            }
            launched != null
        }
        return requireNotNull(launched)
    }

    private fun selectContainer(activity: Activity, file: File) {
        installDocument(file)
        val picked = DocumentsContract.buildDocumentUri("org.decentwallet.wallet.client.test.walletprovider", "wallet")
        context.contentResolver.persistedUriPermissions
            .filter { it.uri == picked && it.isReadPermission }
            .forEach { context.contentResolver.releasePersistableUriPermission(it.uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
        openPicker(activity)
        waitUntil("DocumentsUI accessibility root") { pickerRoot() != null }
        val pickerRoot = requireNotNull(pickerRoot())
        if (findNode(pickerRoot, "Qualification wallets") == null) {
            val drawer = findNodeDescription(pickerRoot) { "root" in it.lowercase() || "navigation" in it.lowercase() }
            assertNotNull("DocumentsUI did not expose its locations drawer", drawer)
            assertTrue("could not open DocumentsUI locations", requireNotNull(drawer).performAction(AccessibilityNodeInfo.ACTION_CLICK))
        }
        clickPickerText("Qualification wallets")
        waitForPickerText("synthetic-wallet.bin")
        clickPickerText("synthetic-wallet.bin")
        var openAction: String? = null
        waitUntil("file selection or picker return") {
            openAction = listOf("Open", "OPEN", "open").firstOrNull { label ->
                pickerRoot()?.let { findNode(it, label) != null } == true
            }
            (isActivityResumed(activity) && !documentsUiIsActive()) || openAction != null
        }
        if (!isActivityResumed(activity) || documentsUiIsActive()) {
            clickPickerText(requireNotNull(openAction) { "DocumentsUI selected no file and exposed no Open action" })
        }
        waitUntil("picker returning to qualification app") { isActivityResumed(activity) && !documentsUiIsActive() }
        val persisted = context.contentResolver.persistedUriPermissions.any { it.uri == picked && it.isReadPermission }
        assertTrue("DocumentsUI did not persist a read grant for selected wallet", persisted)
    }

    private fun installDocument(source: File) {
        val uri = Uri.parse("content://$FIXTURE_AUTHORITY/document")
        val descriptor = checkNotNull(testContext.contentResolver.openFileDescriptor(uri, "w"))
        ParcelFileDescriptor.AutoCloseOutputStream(descriptor).use { output ->
            source.inputStream().use { input -> input.copyTo(output) }
        }
    }

    private fun openPicker(activity: Activity) {
        clickAppText(activity, "Choose encrypted wallet")
        waitUntil("Android DocumentsUI") { pickerRoot()?.packageName?.contains("documentsui") == true }
    }

    private fun clickPickerText(label: String) {
        waitUntil("DocumentsUI item $label") {
            val root = pickerRoot()
            root != null && findNode(root, label) != null
        }
        val root = requireNotNull(pickerRoot())
        val node = requireNotNull(findNode(root, label))
        if (label != "synthetic-wallet.bin") {
            var clickable = node
            while (!clickable.isClickable && clickable.parent != null) clickable = requireNotNull(clickable.parent)
            if (clickable.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return
        }
        val bounds = Rect()
        node.getBoundsInScreen(bounds)
        assertFalse("DocumentsUI item $label has no tappable bounds", bounds.isEmpty)
        val x = bounds.centerX().toFloat()
        val y = bounds.centerY().toFloat()
        val downTime = SystemClock.uptimeMillis()
        val down = MotionEvent.obtain(downTime, downTime, MotionEvent.ACTION_DOWN, x, y, 0)
        val up = MotionEvent.obtain(downTime, downTime + 50, MotionEvent.ACTION_UP, x, y, 0)
        down.source = InputDevice.SOURCE_TOUCHSCREEN
        up.source = InputDevice.SOURCE_TOUCHSCREEN
        try {
            assertTrue("could not tap DocumentsUI item $label", instrumentation.uiAutomation.injectInputEvent(down, true))
            assertTrue("could not release DocumentsUI item $label", instrumentation.uiAutomation.injectInputEvent(up, true))
        } finally {
            down.recycle()
            up.recycle()
        }
    }

    private fun waitForPickerText(label: String) = waitUntil("DocumentsUI item $label") {
        pickerRoot()?.let { findNode(it, label) != null } == true
    }

    private fun findNode(node: AccessibilityNodeInfo, label: String): AccessibilityNodeInfo? {
        if (node.text?.toString() == label || node.contentDescription?.toString() == label) return node
        for (index in 0 until node.childCount) {
            val child = node.getChild(index) ?: continue
            findNode(child, label)?.let { return it }
        }
        return null
    }

    private fun findNodeDescription(node: AccessibilityNodeInfo, predicate: (String) -> Boolean): AccessibilityNodeInfo? {
        node.contentDescription?.toString()?.let { if (predicate(it)) return node }
        for (index in 0 until node.childCount) {
            val child = node.getChild(index) ?: continue
            findNodeDescription(child, predicate)?.let { return it }
        }
        return null
    }

    private fun clickAppText(activity: Activity, label: String) = runOnMain {
        WalletLoginTestViews.button(activity.window.decorView, label).performClick()
    }

    private fun enter(activity: Activity, identity: String, secret: String) = runOnMain {
        val fields = ArrayList<EditText>()
        fun collect(view: android.view.View) {
            if (view is EditText) fields += view
            if (view is android.view.ViewGroup) {
                for (index in 0 until view.childCount) collect(view.getChildAt(index))
            }
        }
        collect(activity.window.decorView)
        assertEquals("setup must expose exact identity and password inputs", 2, fields.size)
        fields[0].setText(identity)
        fields[1].setText(secret)
        assertTrue("Identity ID input did not retain the supplied value", fields[0].text.toString() == identity)
        assertTrue("password input did not retain the supplied value", fields[1].text.toString() == secret)
    }

    private fun clickUnlock(activity: Activity) = clickAppText(activity, "Unlock wallet")

    private fun waitForStatus(activity: Activity, expected: String) = waitUntil(expected) {
        var visible = false
        runOnMain { visible = WalletLoginTestViews.texts(activity.window.decorView).any { expected in it } }
        visible
    }

    private fun waitUntil(label: String, condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (System.nanoTime() < deadline) {
            if (condition()) return
            Thread.sleep(50)
        }
        throw AssertionError("timed out waiting for $label")
    }

    private fun runOnMain(block: () -> Unit) = instrumentation.runOnMainSync(block)

    private fun pickerRoot(): AccessibilityNodeInfo? {
        val windowsRoot = instrumentation.uiAutomation.windows
            .firstOrNull { it.root?.packageName?.contains("documentsui") == true }?.root
        val activeRoot = instrumentation.uiAutomation.rootInActiveWindow
        return windowsRoot ?: activeRoot?.takeIf { it.packageName?.contains("documentsui") == true }
    }

    private fun documentsUiIsActive(): Boolean = instrumentation.uiAutomation.rootInActiveWindow
        ?.packageName?.toString()?.contains("documentsui", ignoreCase = true) == true

    private fun isActivityResumed(activity: Activity): Boolean {
        var resumed = false
        runOnMain {
            resumed = ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                .contains(activity)
        }
        return resumed
    }

    private fun injectBack(): Boolean {
        val downTime = SystemClock.uptimeMillis()
        val down = instrumentation.uiAutomation.injectInputEvent(
            KeyEvent(downTime, downTime, KeyEvent.ACTION_DOWN, KeyEvent.KEYCODE_BACK, 0), true
        )
        val up = instrumentation.uiAutomation.injectInputEvent(
            KeyEvent(downTime, SystemClock.uptimeMillis(), KeyEvent.ACTION_UP, KeyEvent.KEYCODE_BACK, 0), true
        )
        return down && up
    }

    private fun dismissPicker(activity: Activity) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        var backCount = 0
        var nextBackAt = 0L
        while (System.nanoTime() < deadline) {
            if (isActivityResumed(activity) && !documentsUiIsActive()) return
            if (documentsUiIsActive() && backCount < 3 && System.nanoTime() >= nextBackAt) {
                assertTrue("DocumentsUI did not accept Back for cancellation", injectBack())
                backCount++
                nextBackAt = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500)
            }
            Thread.sleep(50)
        }
        throw AssertionError("timed out waiting for picker dismissal")
    }

    private fun withSyntheticContainer(block: (File) -> Unit) {
        val walletFile = File(context.cacheDir, "qualification-source-${UUID.randomUUID()}.wallet")
        val containerFile = File(context.cacheDir, "qualification-container-${UUID.randomUUID()}.bin")
        val session = AndroidWallet.createWithGeneratedKey(walletFile.toPath(), password, password)
        var bytes: ByteArray? = null
        try {
            bytes = session.exportContainer()
            containerFile.writeBytes(bytes)
            session.close()
            block(containerFile)
        } finally {
            bytes?.fill(0)
            session.close()
            walletFile.delete()
            containerFile.delete()
        }
    }
}

private const val FIXTURE_AUTHORITY = "org.decentwallet.wallet.client.test.fixturestaging"
