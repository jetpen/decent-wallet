package org.decentwallet.interop.lanhost

/** Host-side policy only; the wallet library never owns permission consent. */
class LanAccessGate {
  enum class Decision { REQUEST_PERMISSION, READ_REGISTRY, NONE }

  fun connect(sdk: Int, hasPermission: Boolean): Decision =
    if (sdk >= 37 && !hasPermission) Decision.REQUEST_PERMISSION else Decision.READ_REGISTRY

  fun permissionResult(hasPermission: Boolean): Decision =
    if (hasPermission) Decision.READ_REGISTRY else Decision.NONE
}
