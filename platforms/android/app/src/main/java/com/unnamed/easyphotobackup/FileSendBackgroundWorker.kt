package com.unnamed.easyphotobackup

import android.content.Context
import android.os.Environment
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.coroutines.cancellation.CancellationException

class FileSendBackgroundWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {
    private val testFullFileBackup = TestFullFileBackup(appContext.filesDir.absolutePath)

    // this is very test ofc
    private val foldersToSync = arrayOf("DCIM", "Download", "Pictures", "Videos")

    override suspend fun doWork(): Result {

        val root = Environment.getExternalStorageDirectory().absolutePath

        return try {
            setProgress(workDataOf(
                "status" to "discovering"
            ))

            testFullFileBackup.startDiscovery()
            withContext(Dispatchers.IO) {
                Thread.sleep(5 * 1000)
            }
            val discoveryResults = testFullFileBackup.getDiscoveryResults()
            testFullFileBackup.stopDiscovery()

            if (!discoveryResults.isEmpty()) {
                for (discoveryResult in discoveryResults) {
                    val serverName = testFullFileBackup.requestServerName(discoveryResult)

                    if (!testFullFileBackup.isServerPaired(discoveryResult)) {

                        val liveDangerously = false
                        if (liveDangerously) {
                            // DANGER!
                            testFullFileBackup.pairAndApproveServer(discoveryResult)
                        } else {
                            continue
                        }
                    }

                    for (folder in foldersToSync) {
                        setProgress(workDataOf(
                            "status" to "sending $folder to $serverName"
                        ))

                        val folderPath = "$root/$folder"
                        testFullFileBackup.sendFiles(discoveryResult, folderPath, root)
                    }
                }

                setProgress(workDataOf(
                    "status" to "completed"
                ))
            }
            else {
                setProgress(workDataOf(
                    "status" to "no servers"
                ))
            }

            Result.success()
        } catch (e: CancellationException) {
            // ToDo: stop sending files here
            setProgress(workDataOf(
                "status" to "cancelled"
            ))
            Result.retry()
        } catch (e: Exception) {
            setProgress(workDataOf(
                "status" to "exception caught $e"
            ))
            Result.retry()
        }
    }
}
