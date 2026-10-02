package org.decentwallet.interop.lanhost

import org.junit.Assert.assertEquals
import org.junit.Test

class LanAccessGateTest {
  @Test fun sdk37RequestsPermissionBeforeAnyRead() {
    assertEquals(LanAccessGate.Decision.REQUEST_PERMISSION, LanAccessGate().connect(37, false))
  }
  @Test fun legacySdkReadsWithoutRequestingUnsupportedPermission() {
    assertEquals(LanAccessGate.Decision.READ_REGISTRY, LanAccessGate().connect(26, false))
  }
  @Test fun denialDoesNotStartARead() {
    assertEquals(LanAccessGate.Decision.NONE, LanAccessGate().permissionResult(false))
  }
  @Test fun grantPermitsARead() {
    assertEquals(LanAccessGate.Decision.READ_REGISTRY, LanAccessGate().permissionResult(true))
  }
  @Test fun revocationIsRecheckedRatherThanCachingAGrant() {
    val gate = LanAccessGate()
    assertEquals(LanAccessGate.Decision.READ_REGISTRY, gate.connect(37, true))
    assertEquals(LanAccessGate.Decision.REQUEST_PERMISSION, gate.connect(37, false))
  }
}
