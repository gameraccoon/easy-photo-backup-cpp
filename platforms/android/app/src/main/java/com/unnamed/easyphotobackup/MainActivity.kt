package com.unnamed.easyphotobackup

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.unnamed.easyphotobackup.databinding.ActivityMainBinding
import androidx.core.net.toUri
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    @RequiresApi(Build.VERSION_CODES.R)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        ensureAllFilesAccess()

        val prefs = getSharedPreferences("backup_prefs", Context.MODE_PRIVATE)
        binding.sampleText.text = "initialization..."
        WorkManager.getInstance(this)
            .getWorkInfosForUniqueWorkLiveData("file_backup")
            .observe(this) { workInfos ->
                val info = workInfos.firstOrNull() ?: return@observe

                if (info.state == WorkInfo.State.RUNNING) {
                    binding.sampleText.text = info.progress.getString("status") ?: "running without status"
                } else {
                    val lastStatus = prefs.getString("last_status", "waiting for the worker thread to start")
                    binding.sampleText.text = lastStatus
                }
            }

        binding.discoverButton.setOnClickListener {
            val request = PeriodicWorkRequestBuilder<FileSendBackgroundWorker>(
                3, TimeUnit.MINUTES
            ).build()

            WorkManager.getInstance(this)
                .enqueueUniquePeriodicWork(
                    "file_backup",
                    ExistingPeriodicWorkPolicy.REPLACE,
                    request
                )
        }
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun ensureAllFilesAccess() {
        if (!Environment.isExternalStorageManager()) {
            val intent = Intent(
                Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                "package:$packageName".toUri()
            )
            startActivity(intent)
        }
    }
}
