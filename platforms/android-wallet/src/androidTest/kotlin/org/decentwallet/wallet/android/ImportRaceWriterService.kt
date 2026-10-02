package org.decentwallet.wallet.android

import android.app.Service
import android.content.Intent
import android.os.IBinder
import java.nio.file.Files
import java.nio.file.Paths

abstract class ImportRaceWriterService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val request = requireNotNull(intent)
        val directory = Paths.get(requireNotNull(request.getStringExtra(EXTRA_DIRECTORY)))
        val destination = Paths.get(requireNotNull(request.getStringExtra(EXTRA_DESTINATION)))
        val contender = requireNotNull(request.getStringExtra(EXTRA_CONTENDER))
        val password = requireNotNull(request.getStringExtra(EXTRA_PASSWORD))
        Thread({
            Files.write(directory.resolve("started-$contender"), byteArrayOf(1))
            var failureDetail = "none"
            val outcome = try {
                val input = Files.readAllBytes(directory.resolve("input-$contender.dw"))
                try {
                    AtomicWalletFiles.withBeforeCreateInstallForTest(directory, {
                        Files.createFile(directory.resolve("ready-$contender"))
                        awaitOtherWriter(directory, contender)
                    }) {
                        AndroidWallet.importContainer(destination, input, password).close()
                    }
                    "SUCCESS"
                } finally {
                    input.fill(0)
                }
            } catch (failure: Exception) {
                failureDetail = "${failure.javaClass.name}:${failure.message}"
                "STORAGE_FAILURE"
            }
            Files.write(
                directory.resolve("result-$contender.txt"),
                "${android.os.Process.myPid()}:$outcome:$failureDetail".toByteArray(Charsets.UTF_8),
            )
            stopSelf(startId)
        }, "wallet-import-race-$contender").start()
        return START_NOT_STICKY
    }

    private fun awaitOtherWriter(directory: java.nio.file.Path, contender: String) {
        val other = if (contender == "first") "second" else "first"
        val ready = directory.resolve("ready-$other")
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(60)
        while (!Files.exists(ready) && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        check(Files.exists(ready)) { "peer writer did not reach the install boundary" }
    }

    companion object {
        const val EXTRA_DIRECTORY = "directory"
        const val EXTRA_DESTINATION = "destination"
        const val EXTRA_CONTENDER = "contender"
        const val EXTRA_PASSWORD = "password"
    }
}

class ImportRaceWriterOneService : ImportRaceWriterService()

class ImportRaceWriterTwoService : ImportRaceWriterService()
