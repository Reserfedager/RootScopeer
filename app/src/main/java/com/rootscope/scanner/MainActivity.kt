package com.rootscope.scanner

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.rootscope.scanner.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnScan.setOnClickListener { startScan() }
        binding.btnClear.setOnClickListener {
            binding.tvLog.text = ""
        }
        binding.btnCopy.setOnClickListener { copyLog() }
    }

    private fun startScan() {
        binding.btnScan.isEnabled = false
        binding.tvLog.text = "Сканирование...\n"

        lifecycleScope.launch {
            val report = withContext(Dispatchers.IO) {
                Scanner.runFullScan()
            }
            binding.tvLog.text = report
            binding.btnScan.isEnabled = true
            binding.scroll.post {
                binding.scroll.fullScroll(android.view.View.FOCUS_DOWN)
            }
        }
    }

    private fun copyLog() {
        val text = binding.tvLog.text?.toString().orEmpty()
        if (text.isBlank()) {
            Toast.makeText(this, "Лог пустой", Toast.LENGTH_SHORT).show()
            return
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("RootScope log", text))
        Toast.makeText(this, "Лог скопирован", Toast.LENGTH_SHORT).show()
    }
}
