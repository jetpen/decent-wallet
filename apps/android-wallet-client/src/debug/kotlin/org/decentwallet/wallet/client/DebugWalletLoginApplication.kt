package org.decentwallet.wallet.client

import android.app.Activity
import android.app.Application

/** Debug-only host bridge; production releases have no mutable wallet-login test host. */
class DebugWalletLoginApplication : Application(), WalletLoginHost {
    override fun acquireWalletLoginIdentity(activity: Activity): WalletLoginIdentity? = installedIdentity
    override fun nativeDisclosureTrust(activity: Activity): NativeDisclosureTrustConfig? = installedNativeTrust

    companion object {
        @Volatile
        private var installedIdentity: WalletLoginIdentity? = null
        @Volatile
        private var installedNativeTrust: NativeDisclosureTrustConfig? = null

        @JvmStatic
        fun install(identity: WalletLoginIdentity, nativeTrust: NativeDisclosureTrustConfig? = null) {
            check(installedIdentity == null) { "test wallet already installed" }
            installedIdentity = identity
            installedNativeTrust = nativeTrust
        }

        @JvmStatic
        fun clear() {
            installedIdentity = null
            installedNativeTrust = null
        }
    }
}
