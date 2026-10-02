package org.decentwallet.interop.lanhost

import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class ReadWorkerLifecycleTest {
  @Test fun slowThrowingCloseStaysOnWorkerAndDoesNotDelayDestroy() {
    val started = CountDownLatch(1)
    val closing = CountDownLatch(1)
    val release = CountDownLatch(1)
    var closeThread: Thread? = null
    var failure: Throwable? = null
    val worker = Thread {
      try {
        Closeable {
          closeThread = Thread.currentThread()
          closing.countDown()
          release.await(5, TimeUnit.SECONDS)
          error("cleanup failure")
        }.use {
          started.countDown()
          try { CountDownLatch(1).await() } catch (_: InterruptedException) { }
        }
      } catch (caught: Throwable) { failure = caught }
    }
    worker.start()
    assertTrue(started.await(5, TimeUnit.SECONDS))
    val events = mutableListOf<String>()
    try {
      cancelReadWorker(worker, { events.add("destroyed") }, { events.add("super") })
      assertEquals(listOf("destroyed", "super"), events)
      assertTrue(closing.await(5, TimeUnit.SECONDS))
      assertTrue(worker.isAlive)
      assertSame(worker, closeThread)
    } finally { release.countDown(); worker.join(5000) }
    assertFalse(worker.isAlive)
    assertEquals("cleanup failure", failure?.message)
  }

  @Test fun cancellationFollowsDestroyedAndSuperRunsEvenWhenInterruptThrows() {
    val events = mutableListOf<String>()
    val worker = object : Thread() {
      override fun interrupt() { events.add("interrupt"); error("cancel failure") }
    }
    try {
      cancelReadWorker(worker, { events.add("destroyed") }, { events.add("super") })
      fail("expected cancellation failure")
    } catch (failure: IllegalStateException) {
      assertEquals("cancel failure", failure.message)
    }
    assertEquals(listOf("destroyed", "interrupt", "super"), events)
  }
}
