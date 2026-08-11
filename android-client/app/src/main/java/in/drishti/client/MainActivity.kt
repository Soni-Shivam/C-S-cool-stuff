package in.drishti.client

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle

class MainActivity : ComponentActivity() {
    private val viewModel: DrishtiViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        createNotificationChannel()
        handleIncoming(intent)
        setContent {
            MaterialTheme {
                Surface(Modifier.fillMaxSize()) {
                    val state by viewModel.state.collectAsStateWithLifecycle()
                    val picker = rememberLauncherForActivityResult(
                        ActivityResultContracts.OpenDocument()
                    ) { uri -> uri?.let { viewModel.acceptUri(it, contentResolver) } }
                    LaunchedEffect(state) {
                        if (state is UiState.Complete) showCompleteNotification()
                    }
                    DrishtiApp(
                        state = state,
                        onConfigure = viewModel::configure,
                        onPick = { picker.launch(arrayOf(
                            "application/vnd.android.package-archive",
                            "application/zip",
                            "application/octet-stream",
                        )) },
                        onRetry = viewModel::retry,
                        onDelete = viewModel::deleteAndReset,
                        onSettings = viewModel::showConfiguration,
                        onInstall = ::continueToInstaller,
                    )
                }
            }
        }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 42)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncoming(intent)
    }

    private fun handleIncoming(intent: Intent?) {
        val uri: Uri? = when (intent?.action) {
            Intent.ACTION_SEND -> intent.getParcelableExtra(Intent.EXTRA_STREAM)
            Intent.ACTION_VIEW -> intent.data
            else -> null
        }
        uri?.let { viewModel.acceptUri(it, contentResolver) }
    }

    private fun continueToInstaller(complete: UiState.Complete) {
        if (!packageManager.canRequestPackageInstalls()) {
            startActivity(Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:$packageName"),
            ))
            return
        }
        val uri = FileProvider.getUriForFile(this, "$packageName.files", complete.localFile)
        startActivity(Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        })
    }

    private fun createNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(
            "analysis", "Analysis results", NotificationManager.IMPORTANCE_DEFAULT
        ))
    }

    private fun showCompleteNotification() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val notification = NotificationCompat.Builder(this, "analysis")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Analysis complete")
            .setContentText("Open DRISHTI to review the pre-install verdict.")
            .setAutoCancel(true)
            .build()
        NotificationManagerCompat.from(this).notify(7001, notification)
    }
}
