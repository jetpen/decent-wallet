package org.decentwallet.interop.lanhost

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.platform.app.InstrumentationRegistry
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import org.junit.Assert.*
import org.junit.Test

class LanPermissionRuntimeTest {
  @Test fun consumingHostChecksPermissionBeforeRealRemoteRegistryReads() {
    val instrumentation = InstrumentationRegistry.getInstrumentation()
    val args = InstrumentationRegistry.getArguments()
    assertEquals(checkNotNull(args.getString("expectedApi")).toInt(), Build.VERSION.SDK_INT)
    assertEquals(args.getString("expectedAbi"), Build.SUPPORTED_ABIS.first())
    val scenario = checkNotNull(args.getString("scenario"))
    val peer = checkNotNull(args.getString("writerPeer"))
    val readback = checkNotNull(args.getString("readbackPeer"))
    require(peer.startsWith("/ip4/10.0.2.2/tcp/") && readback.startsWith("/ip4/10.0.2.2/tcp/"))
    val context = instrumentation.targetContext
    val intent = Intent(context, LanPermissionActivity::class.java)
      .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      .putExtra("writerPeer", peer).putExtra("readbackPeer", readback)
    val activity = instrumentation.startActivitySync(intent) as LanPermissionActivity
    try {
      assertEquals(37, context.applicationInfo.targetSdkVersion)
      if (Build.VERSION.SDK_INT >= 37) {
        assertEquals(PackageManager.PERMISSION_DENIED, context.checkSelfPermission(LanPermissionActivity.LAN_PERMISSION))
        if (scenario == "revoked") {
          assertTrue(activity.previouslyGranted)
        }
        // Genuine protected-address TCP attempt, paired with later successful reads
        // through the exact same live forwards after system consent.
        val port = peer.substringAfter("/tcp/").substringBefore('/').toInt()
        try {
          Socket().use { it.connect(InetSocketAddress("10.0.2.2", port), 1500) }
          fail("ungranted protected LAN socket unexpectedly connected")
        } catch (_: IOException) { }
      }
      instrumentation.runOnMainSync { activity.requestRead() }
      if (Build.VERSION.SDK_INT >= 37) {
        waitUntil { activity.status == "REQUESTING" }
        assertEquals(0, activity.readStarts)
        clickSystemPermission(if (scenario == "granted") "permission_allow_button" else "permission_deny_button")
      }
      if (scenario == "granted" || scenario == "legacy") {
        waitUntil { activity.status == "OK" || activity.status == "FAILED" }
        assertEquals("OK", activity.status)
        assertEquals(1, activity.readStarts)
        assertEquals(if (Build.VERSION.SDK_INT >= 37) 1 else 0, activity.permissionRequests)
        if (Build.VERSION.SDK_INT >= 37) {
          assertEquals(PackageManager.PERMISSION_GRANTED, context.checkSelfPermission(LanPermissionActivity.LAN_PERMISSION))
          assertTrue(activity.previouslyGranted)
        }
      } else {
        waitUntil { activity.status == "DENIED" }
        assertEquals(0, activity.readStarts)
        assertEquals(1, activity.permissionRequests)
        assertEquals(PackageManager.PERMISSION_DENIED, context.checkSelfPermission(LanPermissionActivity.LAN_PERMISSION))
      }
      println("LAN_HOST scenario=$scenario sdk=${Build.VERSION.SDK_INT} status=${activity.status} requests=${activity.permissionRequests} realReadStarts=${activity.readStarts}")
    } finally {
      instrumentation.runOnMainSync { activity.finish() }
    }
  }

  private fun waitUntil(predicate: () -> Boolean) {
    val deadline = System.nanoTime() + 60_000_000_000L
    while (System.nanoTime() < deadline) {
      if (predicate()) return
      Thread.sleep(100)
    }
    error("LAN host condition timed out")
  }

  private fun clickSystemPermission(button: String) {
    val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
    val info = automation.serviceInfo
    info.flags = info.flags or android.accessibilityservice.AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
    automation.serviceInfo = info
    waitUntil {
      val root = automation.rootInActiveWindow ?: return@waitUntil false
      try {
        for (pkg in listOf("com.google.android.permissioncontroller", "com.android.permissioncontroller")) {
          for (node in root.findAccessibilityNodeInfosByViewId("$pkg:id/$button")) {
            try {
              if (node.isClickable && node.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return@waitUntil true
            } finally { node.recycle() }
          }
        }
        false
      } finally { root.recycle() }
    }
  }
}
