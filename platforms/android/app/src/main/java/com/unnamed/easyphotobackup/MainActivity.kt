package com.unnamed.easyphotobackup

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

        binding.sampleText.text = "Waiting for worker thread to start"
        WorkManager.getInstance(this)
            .getWorkInfosForUniqueWorkLiveData("file_backup")
            .observe(this) { workInfos ->
                val info = workInfos.firstOrNull()

                if (info != null) {
                    val progress = info.progress.getString("status")
                    if (progress != null) {
                        binding.sampleText.text = progress
                    } else {
                        binding.sampleText.text = "Waiting for worker to run"
                    }
                } else {
                    binding.sampleText.text = "Waiting for status from worker thread"
                }
            }

        val workManager = WorkManager.getInstance(this)

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
