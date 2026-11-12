package org.decentwallet.wallet.client

import java.util.concurrent.atomic.AtomicInteger

/** Linearizes cancellation against proof generation and the exact start of network submission. */
internal class ApprovalAttemptGate {
    private val state = AtomicInteger(PENDING)

    val isCancelled: Boolean get() = state.get() == CANCELLED

    fun cancel(): Boolean {
        while (true) {
            val current = state.get()
            if (current == CANCELLED || current == SUBMISSION_STARTED) return false
            if (state.compareAndSet(current, CANCELLED)) return true
        }
    }

    fun <P, R> approve(
        createProof: () -> P,
        beforeSubmit: () -> Boolean = { true },
        submit: (P) -> R,
    ): R? {
        if (!state.compareAndSet(PENDING, PROOFING)) return null
        val proof = createProof()
        if (!beforeSubmit()) return null
        if (!state.compareAndSet(PROOFING, SUBMISSION_STARTED)) return null
        return submit(proof)
    }

    companion object {
        private const val PENDING = 0
        private const val PROOFING = 1
        private const val SUBMISSION_STARTED = 2
        private const val CANCELLED = 3
    }
}
