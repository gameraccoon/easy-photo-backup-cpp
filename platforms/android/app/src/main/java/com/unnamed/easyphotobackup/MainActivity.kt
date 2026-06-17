package com.unnamed.easyphotobackup

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.EditText
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.unnamed.easyphotobackup.databinding.ActivityMainBinding
import androidx.core.net.toUri

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val testFullFileBackup = TestFullFileBackup()

    private var isDiscovering = false;

    @RequiresApi(Build.VERSION_CODES.R)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        ensureAllFilesAccess()

        discoverServers()
        val discoverButton = findViewById<View>(R.id.discoverButton) as Button
        discoverButton.setOnClickListener {
            discoverServers()
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

    @RequiresApi(Build.VERSION_CODES.R)
    private fun discoverServers() {
        if (isDiscovering) {
            return
        }

        testFullFileBackup.startDiscovery()
        isDiscovering = true
        (findViewById<View>(R.id.discoverButton) as Button).isEnabled = false

        val handler = Handler(mainLooper)
        handler.postDelayed({
            isDiscovering = false
            (findViewById<View>(R.id.discoverButton) as Button).isEnabled = true

            val discoveryResults = testFullFileBackup.getDiscoveryResults()
            testFullFileBackup.stopDiscovery()

            binding.buttonContainer.removeAllViews()

            if (discoveryResults.isEmpty()) {
                binding.sampleText.text = "No servers found"
                return@postDelayed
            }

            binding.sampleText.text = "Found ${discoveryResults.size} server(s)"

            for (result in discoveryResults) {
                val serverName = testFullFileBackup.requestServerName(result)

                val button = Button(this).apply {
                    text = serverName
                }

                button.setOnClickListener {

                    testFullFileBackup.pairAndApproveServer(result, serverName)

                    if (!Environment.isExternalStorageManager()) {
                        ensureAllFilesAccess()
                        return@setOnClickListener
                    }

                    val root = Environment.getExternalStorageDirectory().absolutePath

                    val text = findViewById<View>(R.id.folderPathText) as EditText
                    val relativePath = text.text.toString()
                    val folderPath = "$root/$relativePath"

                    testFullFileBackup.sendFiles(
                        result,
                        serverName,
                        folderPath
                    )

                    binding.sampleText.text = "Sending from: $folderPath"
                }

                binding.buttonContainer.addView(button)
            }

        }, 2000)
    }

    @RequiresApi(Build.VERSION_CODES.R)
    override fun onResume() {
        super.onResume()

        if (Environment.isExternalStorageManager()) {
            binding.sampleText.text = "Storage access granted"
        }
    }
}
