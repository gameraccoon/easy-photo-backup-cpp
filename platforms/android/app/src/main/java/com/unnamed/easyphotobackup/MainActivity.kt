package com.unnamed.easyphotobackup

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.Handler
import com.unnamed.easyphotobackup.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var testFullFileBackup: TestFullFileBackup = TestFullFileBackup()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        testFullFileBackup.startDiscovery();

        val delayedHandler = Handler()
        delayedHandler.postDelayed({
            val discoveryResults = testFullFileBackup.getDiscoveryResults()
            testFullFileBackup.stopDiscovery();

            if (discoveryResults.isEmpty()) {
                binding.sampleText.text = "No server found"
            } else {
                val serverName = testFullFileBackup.requestServerName(discoveryResults[0])

                testFullFileBackup.pairAndApproveServer(discoveryResults[0], serverName)

                //testFullFileBackup.sendFiles(discoveryResults[0], serverName, "")

                binding.sampleText.text = serverName
            }

        }, 2000)
    }
}
