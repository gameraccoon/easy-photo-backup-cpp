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

        val delayedHandler = Handler()
        delayedHandler.postDelayed({
            binding.sampleText.text = testFullFileBackup.requestServerName("192.168.0.103", 51709)
        }, 2000)

    }
}
