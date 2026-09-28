package org.decentwallet.wallet.android

open class WalletContainerException internal constructor(message: String) : Exception(message)

class WalletLockedException : WalletContainerException("wallet is locked")

class WalletPasswordPolicyException : WalletContainerException("wallet password policy rejected")

class WalletUnlockException : WalletContainerException("wallet unlock failed")

class WalletInvalidContainerException : WalletContainerException("wallet container is invalid")

class WalletUnsupportedFormatException : WalletContainerException("wallet format is unsupported")

class WalletStorageException : WalletContainerException("wallet storage operation failed")

class WalletStorageOutcomeUnknownException : WalletContainerException("wallet storage outcome is unknown")

class WalletKeyGenerationException : WalletContainerException("key generation failed")

class WalletSigningException : WalletContainerException("signing operation failed")

class WalletRotationInProgressException : WalletContainerException("owner-key rotation is unresolved")

class WalletInvalidIdentityStateException : WalletContainerException("identity state is invalid")

class WalletUnsupportedIdentityStateException : WalletContainerException("identity state format is unsupported")
