package org.decentwallet.wallet.client

import android.app.Activity
import android.app.Application

/** Debug-only host bridge; production releases have no mutable wallet-login test host. */
class DebugWalletLoginApplication : Application(), WalletLoginHost {
    override fun acquireWalletLoginIdentity(activity: Activity): WalletLoginIdentity? = installedIdentity

    companion object {
        @Volatile
        private var installedIdentity: WalletLoginIdentity? = null

        @JvmStatic
        fun install(identity: WalletLoginIdentity) {
            check(installedIdentity == null) { "test wallet already installed" }
            installedIdentity = identity
        }

        @JvmStatic
        fun clear() {
            installedIdentity = null
        }
    }
}
