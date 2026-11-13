package org.decentwallet.wallet.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class ApprovalAttemptGateTest {
    @Test fun cancellationDuringProofGenerationPreventsPost() {
        val gate = ApprovalAttemptGate()
        val proofStarted = CountDownLatch(1)
        val continueProof = CountDownLatch(1)
        val posts = AtomicInteger()
        var outcome: Boolean? = null
        val worker = Thread {
            outcome = gate.approve(
                createProof = {
                    proofStarted.countDown()
                    check(continueProof.await(5, TimeUnit.SECONDS))
                    "proof"
                },
                submit = { posts.incrementAndGet(); true },
            )
        }
        worker.start()
        assertTrue(proofStarted.await(5, TimeUnit.SECONDS))
        assertTrue(gate.cancel())
        continueProof.countDown()
        worker.join(5000)
        assertFalse(worker.isAlive)
        assertEquals(0, posts.get())
        assertNull(outcome)
    }

    @Test fun cancellationAtPreSubmitDecisionPreventsPost() {
        val gate = ApprovalAttemptGate()
        val preSubmit = CountDownLatch(1)
        val continueDecision = CountDownLatch(1)
        val posts = AtomicInteger()
        var outcome: Boolean? = null
        val worker = Thread {
            outcome = gate.approve(
                createProof = { "proof" },
                beforeSubmit = {
                    preSubmit.countDown()
                    check(continueDecision.await(5, TimeUnit.SECONDS))
                    true
                },
                submit = { posts.incrementAndGet(); true },
            )
        }
        worker.start()
        assertTrue(preSubmit.await(5, TimeUnit.SECONDS))
        assertTrue(gate.cancel())
        continueDecision.countDown()
        worker.join(5000)
        assertFalse(worker.isAlive)
        assertEquals(0, posts.get())
        assertNull(outcome)
    }

    @Test fun affirmativeConsentCannotBeReusedForASecondPromptOrProofPost() {
        val gate = ApprovalAttemptGate()
        val prompts = AtomicInteger(1)
        val proofCreations = AtomicInteger()
        val posts = AtomicInteger()
        assertEquals("accepted", gate.approve(
            createProof = { proofCreations.incrementAndGet(); "proof" },
            submit = { posts.incrementAndGet(); "accepted" },
        ))
        assertNull(gate.approve(
            createProof = { prompts.incrementAndGet(); proofCreations.incrementAndGet(); "proof-again" },
            submit = { posts.incrementAndGet(); "accepted-again" },
        ))
        assertEquals(1, prompts.get())
        assertEquals(1, proofCreations.get())
        assertEquals(1, posts.get())
    }

    @Test fun submissionDecisionAndCancellationAreMutuallyExclusive() {
        val gate = ApprovalAttemptGate()
        var submitted = false
        assertTrue(gate.approve(createProof = { "proof" }, submit = { submitted = true; true }) == true)
        assertTrue(submitted)
        assertFalse(gate.cancel())
    }
}
