package org.decentwallet.interop.lanhost

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import org.decentwallet.wallet.android.AndroidDirectDhtIdentityTransport
import org.decentwallet.wallet.android.AndroidRegistryDhtConfig

/** Explicit test-only consumer; not a production wallet or library permission API. */
class LanPermissionActivity : Activity() {
  companion object {
    const val LAN_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"
    private const val REQUEST_LAN = 18
  }
  private val gate = LanAccessGate()
  private lateinit var message: TextView
  @Volatile var status = "IDLE"
    private set
  var permissionRequests = 0
    private set
  var readStarts = 0
    private set
  @Volatile private var destroyed = false
  private var worker: Thread? = null
  val previouslyGranted: Boolean
    get() = getSharedPreferences("test-consent", MODE_PRIVATE).getBoolean("granted", false)

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val layout = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(32, 32, 32, 32)
    }
    layout.addView(TextView(this).apply {
      text = "Test-only Registry reader. LAN permission permits broad local-network access. " +
        "Only explicitly configured test peers are contacted. Denial starts no Registry RPC. " +
        "The wallet library never requests this permission."
    })
    message = TextView(this).apply { text = "No Registry read has started." }
    layout.addView(message)
    layout.addView(Button(this).apply {
      text = "Read configured test Registry"
      setOnClickListener { requestRead() }
    })
    setContentView(layout)
  }

  private fun hasLanPermission(): Boolean = Build.VERSION.SDK_INT < 37 ||
    checkSelfPermission(LAN_PERMISSION) == PackageManager.PERMISSION_GRANTED

  fun requestRead() {
    if (destroyed || status == "READING" || status == "REQUESTING") return
    when (gate.connect(Build.VERSION.SDK_INT, hasLanPermission())) {
      LanAccessGate.Decision.REQUEST_PERMISSION -> {
        permissionRequests++
        show("REQUESTING", "Consent is required before a Registry read.")
        requestPermissions(arrayOf(LAN_PERMISSION), REQUEST_LAN)
      }
      LanAccessGate.Decision.READ_REGISTRY -> readRegistry()
      LanAccessGate.Decision.NONE -> show("DENIED", "No Registry read started.")
    }
  }

  override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults)
    if (requestCode != REQUEST_LAN || destroyed) return
    // Recheck OS state instead of caching or trusting a previous callback grant.
    when (gate.permissionResult(hasLanPermission())) {
      LanAccessGate.Decision.READ_REGISTRY -> {
        getSharedPreferences("test-consent", MODE_PRIVATE).edit().putBoolean("granted", true).apply()
        readRegistry()
      }
      else -> show("DENIED", "Permission denied. No Registry RPC started; retry is explicit.")
    }
  }

  private fun readRegistry() {
    if (!hasLanPermission()) {
      show("DENIED", "Permission was revoked. No Registry RPC started.")
      return
    }
    show("READING", "Reading public synthetic Identity from distinct configured peers.")
    readStarts++
    worker = Thread({
      var owner = byteArrayOf()
      var expected = byteArrayOf()
      var writerBytes: ByteArray? = null
      var readbackBytes: ByteArray? = null
      try {
        check(hasLanPermission())
        val peer = checkNotNull(intent.getStringExtra("writerPeer"))
        val readback = checkNotNull(intent.getStringExtra("readbackPeer"))
        require(peer.startsWith("/ip4/10.0.2.2/tcp/") && readback.startsWith("/ip4/10.0.2.2/tcp/"))
        val fixture = assets.open("identity-owner-key-rotation-legacy.json").bufferedReader().use { it.readText() }
        owner = fixtureHex(fixture, "owner_name_utf8_hex")
        expected = fixtureHex(fixture, "predecessor_envelope_cbor_hex")
        AndroidDirectDhtIdentityTransport(AndroidRegistryDhtConfig(
          registryEnvironment = "approved-ben-x260-lan-test-host",
          registryPeers = listOf(peer), readbackPeer = readback, requestTimeoutMillis = 20_000,
        )).use { client ->
          check(!destroyed && hasLanPermission())
          writerBytes = client.getIdentityEnvelope(owner)
          readbackBytes = client.getRemoteIdentityEnvelope(owner)
          check(expected.contentEquals(writerBytes) && expected.contentEquals(readbackBytes))
        }
        runOnUiThread { if (!destroyed) show("OK", "Exact public fixture envelope read from both distinct remote peers.") }
      } catch (failure: Exception) {
        android.util.Log.e("LAN_HOST", "Configured test Registry read failed", failure)
        runOnUiThread { if (!destroyed) show("FAILED", "Registry read failed; no retry or publication.") }
      } finally {
        owner.fill(0)
        expected.fill(0)
        writerBytes?.fill(0)
        readbackBytes?.fill(0)
      }
    }, "test-host-registry-read").apply { start() }
  }

  private fun show(value: String, text: String) {
    status = value
    message.text = text
  }

  private fun fixtureHex(text: String, field: String): ByteArray {
    val value = Regex("\"$field\"\\s*:\\s*\"([0-9a-f]+)\"").find(text)?.groupValues?.get(1)
      ?: error("missing test fixture field")
    return ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
  }

  override fun onDestroy() {
    cancelReadWorker(worker, { destroyed = true }, { super.onDestroy() })
  }
}
