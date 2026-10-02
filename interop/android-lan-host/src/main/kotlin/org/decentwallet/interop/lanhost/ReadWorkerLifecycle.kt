package org.decentwallet.interop.lanhost

/** Cancel without joining or closing worker-owned resources on the lifecycle thread. */
internal fun cancelReadWorker(worker: Thread?, markDestroyed: () -> Unit, destroy: () -> Unit) {
  try {
    markDestroyed()
    worker?.interrupt()
  } finally {
    destroy()
  }
}
