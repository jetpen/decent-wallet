package org.decentwallet.wallet.android

import android.app.Service
import android.content.Intent
import android.os.IBinder
import java.nio.file.Files
import java.nio.file.Paths

abstract class ImportRaceWriterService : Service() {
    @Volatile private var workerThread: Thread? = null
    @Volatile private var activeDirectory: java.nio.file.Path? = null
    @Volatile private var activeContender: String? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val request = requireNotNull(intent)
        val directory = Paths.get(requireNotNull(request.getStringExtra(EXTRA_DIRECTORY)))
        val destination = Paths.get(requireNotNull(request.getStringExtra(EXTRA_DESTINATION)))
        val contender = requireNotNull(request.getStringExtra(EXTRA_CONTENDER))
        val password = requireNotNull(request.getStringExtra(EXTRA_PASSWORD))
        activeDirectory = directory
        activeContender = contender
        val worker = Thread({
            try {
                Files.write(directory.resolve("started-$contender"), byteArrayOf(1))
                var failureDetail = "none"
                val outcome = try {
                    if (request.getStringExtra(EXTRA_OPERATION) == "proof") {
                        runProofRace(request, directory, destination, contender, password)
                        "SUCCESS"
                    } else {
                        runImportRace(directory, destination, contender, password)
                        "SUCCESS"
                    }
                } catch (failure: Exception) {
                    failureDetail = failure.javaClass.name
                    "STORAGE_FAILURE"
                }
                Files.write(
                    directory.resolve("result-$contender.txt"),
                    "${android.os.Process.myPid()}:$outcome:$failureDetail".toByteArray(Charsets.UTF_8),
                )
            } finally {
                try {
                    Files.write(directory.resolve("worker-exited-$contender"), byteArrayOf(1))
                } finally {
                    stopSelf(startId)
                }
            }
        }, "wallet-race-$contender")
        workerThread = worker
        worker.start()
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        try {
            val worker = workerThread
            if (worker != null && worker !== Thread.currentThread()) {
                val workerFinishedWork = activeDirectory?.let { directory ->
                    activeContender?.let { contender -> Files.exists(directory.resolve("worker-exited-$contender")) }
                } == true
                if (worker.isAlive && !workerFinishedWork) worker.interrupt()
                try {
                    worker.join(java.util.concurrent.TimeUnit.SECONDS.toMillis(10))
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
            if (worker?.isAlive != true) {
                workerThread = null
                val directory = activeDirectory
                val contender = activeContender
                if (directory != null && contender != null) {
                    Files.write(directory.resolve("service-stopped-$contender"), byteArrayOf(1))
                }
            }
        } finally {
            super.onDestroy()
        }
    }

    private fun runImportRace(
        directory: java.nio.file.Path,
        destination: java.nio.file.Path,
        contender: String,
        password: String,
    ) {
        val input = Files.readAllBytes(directory.resolve("input-$contender.dw"))
        try {
            AtomicWalletFiles.withBeforeCreateInstallForTest(directory, {
                Files.createFile(directory.resolve("ready-$contender"))
                awaitOtherWriter(directory, contender)
            }) {
                AndroidWallet.importContainer(destination, input, password).close()
            }
        } finally {
            input.fill(0)
        }
    }

    private fun runProofRace(
        request: Intent,
        directory: java.nio.file.Path,
        destination: java.nio.file.Path,
        contender: String,
        password: String,
    ) {
        val challenge = requireNotNull(request.getStringExtra(EXTRA_CHALLENGE))
        AndroidWallet.open(destination, password).use { wallet ->
            val pending = wallet.recoverPendingAccountApprovalAt(System.currentTimeMillis() / 1000)
                ?: throw WalletDisclosureRequestException()
            Files.write(directory.resolve("ready-$contender"), byteArrayOf(1))
            awaitOtherWriter(directory, contender)
            Files.write(directory.resolve("attempting-replace-$contender"), byteArrayOf(1))
            awaitOtherWriter(directory, contender, "attempting-replace")
            AtomicWalletFiles.withBeforeReplaceInstallForTest(destination, { _ ->
                Files.write(directory.resolve("compared-$contender"), byteArrayOf(1))
                awaitFile(directory.resolve("release-replace-$contender"))
            }) {
                wallet.createAccountLoginProof(pending, challenge)
            }
        }
    }

    private fun awaitOtherWriter(directory: java.nio.file.Path, contender: String, prefix: String = "ready") {
        val other = if (contender == "first") "second" else "first"
        awaitFile(directory.resolve("$prefix-$other"))
    }

    private fun awaitFile(path: java.nio.file.Path) {
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(60)
        while (!Files.exists(path) && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        check(Files.exists(path)) { "coordination marker was not written" }
    }

    companion object {
        const val EXTRA_DIRECTORY = "directory"
        const val EXTRA_DESTINATION = "destination"
        const val EXTRA_CONTENDER = "contender"
        const val EXTRA_PASSWORD = "password"
        const val EXTRA_OPERATION = "operation"
        const val EXTRA_CHALLENGE = "challenge"
    }
}

class ImportRaceWriterOneService : ImportRaceWriterService()

class ImportRaceWriterTwoService : ImportRaceWriterService()
