package com.ezpi

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.graphics.Typeface
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {

    private val bg = 0xFF16181D.toInt()
    private val accent = 0xFF39D98A.toInt()
    private val white = 0xFFEDEEF0.toInt()
    private val gray = 0xFF7A7D85.toInt()

    private lateinit var ring: RingView
    private lateinit var statusText: TextView
    private lateinit var subText: TextView
    private val main = Handler(Looper.getMainLooper())
    private var connecting = false

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context?, i: Intent?) {
            val on = i?.getBooleanExtra("on", false) ?: false
            if (!on) showOff() else if (!connecting) showOn()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = bg
        window.navigationBarColor = bg
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 2)
        }

        val density = resources.displayMetrics.density
        fun dp(v: Int) = (v * density).toInt()

        val root = FrameLayout(this).apply { setBackgroundColor(bg) }
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        val title = TextView(this).apply {
            text = "E Z P I"
            setTextColor(white)
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            letterSpacing = 0.5f
            gravity = Gravity.CENTER
        }

        ring = RingView(this).apply {
            layoutParams = LinearLayout.LayoutParams(dp(236), dp(236)).apply {
                topMargin = dp(40); bottomMargin = dp(40)
            }
            setOnClickListener { onTap() }
        }

        statusText = TextView(this).apply {
            text = "OFF"
            setTextColor(gray)
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 26f)
            letterSpacing = 0.3f
            gravity = Gravity.CENTER
        }

        subText = TextView(this).apply {
            text = "tap to connect"
            setTextColor(gray)
            typeface = Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            letterSpacing = 0.2f
            gravity = Gravity.CENTER
            setPadding(0, dp(10), 0, 0)
        }

        col.addView(title)
        col.addView(ring)
        col.addView(statusText)
        col.addView(subText)
        root.addView(col)
        setContentView(root)

        if (intent?.getBooleanExtra("autoconnect", false) == true) onTap()
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter("com.ezpi.STATE")
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(stateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(stateReceiver, filter)
        }
        if (!connecting) {
            if (EzpiVpnService.isRunning) showOn() else showOff()
        }
    }

    override fun onPause() {
        super.onPause()
        try { unregisterReceiver(stateReceiver) } catch (_: Exception) {}
    }

    private fun onTap() {
        if (connecting) return
        if (EzpiVpnService.isRunning || ring.state == RingView.State.ON) {
            disconnect()
        } else {
            val prep = VpnService.prepare(this)
            if (prep != null) startActivityForResult(prep, 1) else beginConnect()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == RESULT_OK) beginConnect()
    }

    private fun beginConnect() {
        connecting = true
        ring.state = RingView.State.CONNECTING
        statusText.setTextColor(accent)
        statusText.text = "CONNECTING"
        subText.text = ""
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(Intent(this, EzpiVpnService::class.java))
        } else {
            startService(Intent(this, EzpiVpnService::class.java))
        }
        main.postDelayed({
            connecting = false
            if (EzpiVpnService.isRunning) showOn() else showOff()
        }, 500)
    }

    private fun disconnect() {
        startService(Intent(this, EzpiVpnService::class.java).setAction(EzpiVpnService.ACTION_STOP))
        showOff()
    }

    private fun showOn() {
        ring.state = RingView.State.ON
        statusText.setTextColor(accent)
        statusText.text = "CONNECTED"
        subText.text = "bypass active"
    }

    private fun showOff() {
        connecting = false
        ring.state = RingView.State.OFF
        statusText.setTextColor(gray)
        statusText.text = "OFF"
        subText.text = "tap to connect"
    }
}
