package com.ezpi

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.ezpi.ezpitun.Ezpitun
import com.ezpi.ezpitun.Protector

class EzpiVpnService : VpnService(), Protector {

    private var pfd: ParcelFileDescriptor? = null
    @Volatile private var running = false
    private var netCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        Log.i("EzPi", "service onCreate")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i("EzPi", "onStartCommand action=${intent?.action}")
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        startForeground(1, buildNotification())
        if (!running) startTunnel()
        return START_STICKY
    }

    private fun startTunnel() {
        try {
            val builder = Builder()
                .setSession("EzPi")
                .setMtu(MTU)
                .addAddress("10.111.0.2", 32)
                .addAddress("fd00::2", 128)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w("EzPi", "disallow self failed", e)
            }
            val fd = builder.establish()
            if (fd == null) {
                Log.e("EzPi", "VpnService.establish() returned null")
                stopSelf()
                return
            }
            pfd = fd
            Log.i("EzPi", "tun fd=${fd.fd}, calling Ezpitun.start")
            Ezpitun.start(fd.fd.toLong(), MTU.toLong(), this)
            running = true
            isRunning = true
            try { setUnderlyingNetworks(null) } catch (e: Throwable) {}
            watchNetwork()
            sendBroadcast(Intent("com.ezpi.STATE").putExtra("on", true).setPackage(packageName))
            Log.i("EzPi", "tunnel established, netstack started")
        } catch (e: Throwable) {
            Log.e("EzPi", "startTunnel failed", e)
            stopTunnel()
            stopSelf()
        }
    }

    private fun watchNetwork() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                try { setUnderlyingNetworks(arrayOf(network)) } catch (e: Throwable) {}
            }
            override fun onLost(network: Network) {
                try { setUnderlyingNetworks(null) } catch (e: Throwable) {}
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            netCallback = cb
        } catch (e: Throwable) {
            Log.w("EzPi", "network callback register failed", e)
        }
    }

    private fun unwatchNetwork() {
        val cb = netCallback ?: return
        netCallback = null
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
        } catch (e: Throwable) {}
    }

    private fun stopTunnel() {
        unwatchNetwork()
        running = false
        isRunning = false
        try { Ezpitun.stop() } catch (e: Exception) { Log.w("EzPi", "stop", e) }
        try { pfd?.close() } catch (e: Exception) { }
        pfd = null
        sendBroadcast(Intent("com.ezpi.STATE").putExtra("on", false).setPackage(packageName))
    }

    override fun protect(fd: Long): Boolean = protect(fd.toInt())

    override fun onRevoke() {
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val channelId = "ezpi"
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(channelId, "EzPi", NotificationManager.IMPORTANCE_LOW)
        )
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, channelId)
            .setContentTitle("EzPi")
            .setContentText("Bypass active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_STOP = "com.ezpi.STOP"
        const val MTU = 1500
        @Volatile var isRunning = false
    }
}
