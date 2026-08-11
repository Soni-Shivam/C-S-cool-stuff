package in.drishti.fixture.shady

import android.app.Activity
import android.os.Bundle
import android.graphics.Color
import android.view.Gravity
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "INERT DRISHTI DEMO FIXTURE\n\nThis app performs no SMS, network, contact, overlay, install, accessibility, or credential actions.\n\nIts suspicious permissions exist only to exercise pre-install static-analysis rules."
            textSize = 20f
            setTextColor(Color.rgb(35, 35, 45))
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        })
    }
}
