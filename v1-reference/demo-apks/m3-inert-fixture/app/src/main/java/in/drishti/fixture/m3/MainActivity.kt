package in.drishti.fixture.m3

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.os.Build
import android.os.Bundle
import android.widget.TextView
import dalvik.system.DexClassLoader
import java.net.HttpURLConnection
import java.net.URL
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val status = mutableListOf<String>()

        val clipboard = getSystemService(ClipboardManager::class.java)
        clipboard.setPrimaryClip(ClipData.newPlainText("fixture", "DRISHTI_FIXTURE_ONLY"))
        clipboard.primaryClip
        status += "clipboard read/write complete"

        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(ByteArray(16) { 7 }, "AES"))
        cipher.doFinal("fixture-dummy-text".toByteArray())
        status += "dummy cipher call complete"

        val loader = DexClassLoader(applicationInfo.sourceDir, codeCacheDir.path, null, classLoader)
        loader.loadClass("in.drishti.fixture.m3.FixtureMarker")
        status += "harmless local class load complete"
        status += "device properties read: ${Build.MANUFACTURER}/${Build.MODEL}/${Build.VERSION.SDK_INT}"

        Thread {
            try {
                val connection = URL("http://10.0.2.2:8080/fixture").openConnection() as HttpURLConnection
                connection.connectTimeout = 1500
                connection.readTimeout = 1500
                connection.requestMethod = "GET"
                connection.responseCode
                connection.disconnect()
            } catch (_: Exception) {
                // Expected when the local no-upstream fake C2 is not running.
            }
        }.start()

        setContentView(TextView(this).apply {
            text = "INERT M3 FIXTURE\n\n" + status.joinToString("\n") +
                "\n\nNo real data is read and no remote service is contacted."
            textSize = 19f
            setPadding(48, 48, 48, 48)
        })
    }
}
