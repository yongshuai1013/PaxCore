package com.yongshuai.paxcore

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.system.Os
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File
import java.io.RandomAccessFile
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipInputStream

/**
 * PaxCore phone shell: extracts the bundled GB rootfs once, then
 * execs libpaxcore.so (the interpreter, shipped in jniLibs and
 * landed in nativeLibraryDir via legacy packaging) against it.
 * The guest's whole boot log streams into a session log file
 * under Android/data/.../files/logs/, written directly by the
 * child process so the record survives this UI dying; the log
 * view only tails that file.
 */
class MainActivity : Activity() {

    private lateinit var statusView: TextView
    private lateinit var logView: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var startButton: Button
    private lateinit var stopButton: Button

    private var process: Process? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var sessionLog: File? = null
    private val ui = Handler(Looper.getMainLooper())
    private var rootfsReady = false

    private val rootfsDir: File get() = File(filesDir, "gbrootfs")
    private val logTailer = object : Runnable {
        override fun run() {
            refreshLogView()
            if (process != null) ui.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
        setStatus("正在準備客體 rootfs…")
        Thread { prepareRootfs() }.start()
    }

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
        }
        statusView = TextView(this).apply { textSize = 14f }
        root.addView(statusView)
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.START
        }
        startButton = Button(this).apply {
            text = "啟動"
            isEnabled = false
            setOnClickListener { startCore() }
        }
        stopButton = Button(this).apply {
            text = "停止"
            isEnabled = false
            setOnClickListener { stopCore() }
        }
        row.addView(startButton)
        row.addView(stopButton)
        root.addView(row)
        logView = TextView(this).apply {
            textSize = 11f
            typeface = android.graphics.Typeface.MONOSPACE
        }
        scrollView = ScrollView(this).apply { addView(logView) }
        root.addView(
            scrollView,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f
            )
        )
        setContentView(root)
    }

    private fun setStatus(text: String) {
        runOnUiThread { statusView.text = text }
    }

    /** Extract gbrootfs.zip once per payload version. The marker
     *  name must bump whenever the zip payload changes, or the
     *  phone keeps running the old tree. Extraction always
     *  clears the old tree first: a previous incident left stale
     *  files poisoning later runs when extraction only overlaid. */
    private fun prepareRootfs() {
        try {
            val marker = File(rootfsDir, ROOTFS_MARKER)
            if (!marker.exists()) {
                deleteTree(rootfsDir)
                rootfsDir.mkdirs()
                extractZip()
                fixupSymlinks()
                marker.writeText("ok")
            }
            cleanRuntimeResidue()
            rootfsReady = true
            setStatus("rootfs 就緒。按下「啟動」開始開機。")
            runOnUiThread { startButton.isEnabled = true }
        } catch (e: Exception) {
            setStatus("rootfs 準備失敗：${e.message}")
        }
    }

    private fun extractZip() {
        val buf = ByteArray(64 * 1024)
        ZipInputStream(assets.open("gbrootfs.zip")).use { zis ->
            var entry = zis.nextEntry
            while (entry != null) {
                val out = File(rootfsDir, entry.name)
                if (entry.isDirectory) {
                    out.mkdirs()
                } else {
                    out.parentFile?.mkdirs()
                    out.outputStream().use { os ->
                        var n = zis.read(buf)
                        while (n > 0) {
                            os.write(buf, 0, n)
                            n = zis.read(buf)
                        }
                    }
                }
                zis.closeEntry()
                entry = zis.nextEntry
            }
        }
    }

    /** java.util.zip cannot restore symlinks: the four root
     *  links of the Android root layout arrive as small plain
     *  files holding their target string. Replace them with
     *  real symlinks so the tree matches the reference rootfs
     *  byte for byte in structure. */
    private fun fixupSymlinks() {
        for ((name, target) in ROOT_SYMLINKS) {
            val link = File(rootfsDir, name)
            if (isSymlink(link)) continue
            if (link.exists() && !link.isDirectory) link.delete()
            if (!link.exists()) {
                try {
                    Os.symlink(target, link.absolutePath)
                } catch (e: Exception) {
                    // Leave it missing if symlink fails; the
                    // guest then sees ENOENT, same as the
                    // reference host where the target is absent.
                }
            }
        }
    }

    /** PaxCore's kernel layer leaves runtime residue inside the
     *  rootfs (mirrors the host boot script's cleanup): wipe it
     *  before every start so a killed run cannot poison the
     *  next one. data/ is kept on purpose (dalvik-cache). */
    private fun cleanRuntimeResidue() {
        for (rel in RESIDUE_DIRS) {
            deleteTree(File(rootfsDir, rel))
        }
        File(rootfsDir, "dev/__null__").delete()
        File(rootfsDir, "dev/__kmsg__").delete()
    }

    private fun deleteTree(f: File) {
        if (!f.exists()) return
        if (f.isDirectory && !isSymlink(f)) {
            f.listFiles()?.forEach { deleteTree(it) }
        }
        f.delete()
    }

    private fun isSymlink(f: File): Boolean =
        try {
            android.system.OsConstants.S_ISLNK(
                Os.lstat(f.absolutePath).st_mode
            )
        } catch (e: Exception) {
            false
        }

    private fun startCore() {
        if (!rootfsReady || process != null) return
        try {
            cleanRuntimeResidue()
            val ts = SimpleDateFormat(
                "yyyyMMdd-HHmmss", Locale.US
            ).format(Date())
            val logDir = File(
                getExternalFilesDir(null), "logs"
            ).apply { mkdirs() }
            val log = File(logDir, "session-$ts.log")
            sessionLog = log
            val libDir = applicationInfo.nativeLibraryDir
            val rootfs = rootfsDir.absolutePath
            val pb = ProcessBuilder(
                listOf(
                    "$libDir/libpaxcore.so",
                    "--rootfs", rootfs,
                    "$rootfs/init"
                )
            )
            pb.directory(filesDir)
            pb.redirectErrorStream(true)
            pb.redirectOutput(log)
            val env = pb.environment()
            // Block cache is disabled (its TEXTREL invalidation
            // is an open case); sampling + a generous step cap
            // mirror the host boot runs so logs stay comparable.
            env["PAXCORE_NOCACHE"] = "1"
            env["PAXCORE_PCSAMPLE"] = "1000000000"
            env["PAXCORE_MAX_STEPS"] = "1000000000000"
            process = pb.start()
            acquireWakeLock()
            startButton.isEnabled = false
            stopButton.isEnabled = true
            setStatus("運行中…日誌：Android/data/com.yongshuai.paxcore/files/logs/${log.name}")
            ui.post(logTailer)
            val p = process
            Thread {
                val rc = try {
                    p?.waitFor()
                } catch (e: Exception) {
                    null
                }
                runOnUiThread {
                    if (process === p) {
                        process = null
                        releaseWakeLock()
                        stopButton.isEnabled = false
                        startButton.isEnabled = true
                        setStatus("已結束（exit=$rc）。日誌：${log.name}")
                        refreshLogView()
                    }
                }
            }.start()
        } catch (e: Exception) {
            setStatus("啟動失敗：${e.message}")
            process = null
        }
    }

    private fun stopCore() {
        val p = process ?: return
        p.destroy()
        Thread {
            Thread.sleep(2000)
            if (p.isAlive) p.destroyForcibly()
        }.start()
    }

    /** Show only the tail of the session log: logs can grow to
     *  hundreds of MB on long boots, and loading one whole into
     *  a String once OOM-killed a shell before (RAM-built full
     *  text). 48 KB from the end is plenty for a live view; the
     *  file on disk keeps everything. */
    private fun refreshLogView() {
        val log = sessionLog ?: return
        try {
            if (!log.exists()) return
            val len = log.length()
            val tail = minOf(len, 48L * 1024)
            val bytes = ByteArray(tail.toInt())
            RandomAccessFile(log, "r").use { raf ->
                raf.seek(len - tail)
                raf.readFully(bytes)
            }
            logView.text = String(bytes, Charsets.UTF_8)
            scrollView.post { scrollView.fullScroll(ScrollView.FOCUS_DOWN) }
        } catch (e: Exception) {
            // A torn read while the child writes is harmless.
        }
    }

    private fun acquireWakeLock() {
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK, "paxcore:run"
        ).apply { acquire(6 * 60 * 60 * 1000L) }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    override fun onDestroy() {
        releaseWakeLock()
        super.onDestroy()
    }

    companion object {
        // Bump when assets/gbrootfs.zip content changes.
        const val ROOTFS_MARKER = ".gbrootfs-v1"
        val ROOT_SYMLINKS = listOf(
            "etc" to "/system/etc",
            "d" to "/sys/kernel/debug",
            "vendor" to "/system/vendor",
            "sdcard" to "/mnt/sdcard"
        )
        val RESIDUE_DIRS = listOf("sys", "dev/pts", "dev/socket")
    }
}
