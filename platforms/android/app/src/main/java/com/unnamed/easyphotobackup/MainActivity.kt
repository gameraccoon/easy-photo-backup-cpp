package com.unnamed.easyphotobackup

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.provider.Settings
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import com.unnamed.easyphotobackup.databinding.ActivityMainBinding
import androidx.core.net.toUri
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var testFullFileBackup: TestFullFileBackup

    private var isDiscovering = false;
    private var isSendingFiles = false;

    @RequiresApi(Build.VERSION_CODES.R)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        testFullFileBackup = TestFullFileBackup(filesDir.absolutePath)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        ensureAllFilesAccess()

        discoverServers()
        binding.discoverButton.setOnClickListener {
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
        binding.sampleText.text = "Discovering servers..."
        binding.discoverButton.isEnabled = false

        val handler = Handler(mainLooper)
        handler.postDelayed({
            isDiscovering = false
            binding.discoverButton.isEnabled = true

            val discoveryResults = testFullFileBackup.getDiscoveryResults()
            testFullFileBackup.stopDiscovery()

            binding.buttonContainer.removeAllViews()

            if (discoveryResults.isEmpty()) {
                binding.sampleText.text = "No servers found"
                return@postDelayed
            }

            binding.sampleText.text = "Found ${discoveryResults.size} server(s)"

            for (result in discoveryResults) {
                var serverName = testFullFileBackup.requestServerName(result)
                if (serverName == null)
                {
                    serverName = "Unknown"
                }

                val title = TextView(this).apply {
                    text = serverName
                }

                val pairButton = Button(this).apply {
                    text = "pair"
                }

                val sendFilesButton = Button(this).apply {
                    text = "send"
                }

                val removeButton = Button(this).apply {
                    text = "x"
                }

                val horizontalBox = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                }

                horizontalBox.addView(title)
                horizontalBox.addView(pairButton)
                horizontalBox.addView(sendFilesButton)
                horizontalBox.addView(removeButton)

                val updateButtonStates = {
                    val isPaired = testFullFileBackup.isServerPaired(serverName)
                    pairButton.isEnabled = !isSendingFiles && !isPaired
                    sendFilesButton.isEnabled = !isSendingFiles && isPaired
                    removeButton.isEnabled = !isSendingFiles && isPaired
                }

                pairButton.setOnClickListener {
                    val result = testFullFileBackup.pairAndApproveServer(result, serverName)
                    if (result == null)
                    {
                        binding.sampleText.text = "Successfully paired"
                    }
                    else
                    {
                        binding.sampleText.text = result
                    }
                    updateButtonStates()
                }

                sendFilesButton.setOnClickListener {
                    if (!Environment.isExternalStorageManager()) {
                        ensureAllFilesAccess()
                        return@setOnClickListener
                    }

                    val root = Environment.getExternalStorageDirectory().absolutePath

                    val text = binding.folderPathText
                    val relativePath = text.text.toString()
                    val folderPath = "$root/$relativePath"

                    binding.sampleText.text = "Sending files"
                    isSendingFiles = true
                    updateButtonStates()
                    sendFiles(lifecycleScope, result, serverName, folderPath, root) { result ->
                        isSendingFiles = false
                        if (result == null)
                        {
                            binding.sampleText.text = "Successfully sent files"
                        }
                        else
                        {
                            binding.sampleText.text = result
                        }
                        updateButtonStates()
                    }
                }

                removeButton.setOnClickListener {
                    val result = testFullFileBackup.removeServer(serverName)
                    if (result == null)
                    {
                        binding.sampleText.text = "Successfully removed"
                    }
                    else
                    {
                        binding.sampleText.text = result
                    }
                    updateButtonStates()
                }

                updateButtonStates()

                binding.buttonContainer.addView(horizontalBox)
            }

        }, 2000)
    }

    fun sendFiles(scope: CoroutineScope, address: String, serverName: String, folderPath: String, commonRoot: String, onComplete: (String?) -> Unit) {
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                testFullFileBackup.sendFiles(
                    address,
                    serverName,
                    folderPath,
                    commonRoot
                )
            }

            onComplete(result)
        }
    }
}
