package `in`.drishti.decoy.rtochallan

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.util.TypedValue
import android.widget.LinearLayout
import android.widget.TextView

/**
 * The only screen. It exists so the APK has a launcher activity like the family does,
 * and it says out loud what this file is — because the worst outcome for a decoy is
 * someone finding it later and not knowing.
 */
class ChallanActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        InertMarker.noop("ChallanActivity.onCreate")
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.WHITE)
            setPadding(48, 96, 48, 48)
        }
        root.addView(label("DRISHTI TEST DECOY", 22f, Color.parseColor("#B00020"), true))
        root.addView(
            label(
                "This is not a real application and it is not malware.\n\n" +
                    "It was authored by the DRISHTI project as an inert detection target. " +
                    "Its manifest declares the permissions of the Indian traffic-challan " +
                    "fraud family so that the static analysis engine has something " +
                    "realistic to detect. Every component in it is a no-op.\n\n" +
                    "It cannot read your messages, draw over other apps, install " +
                    "anything, or contact any server. There is no code in it that does " +
                    "those things.",
                15f, Color.DKGRAY, false,
            )
        )
        setContentView(root)
    }

    private fun label(value: String, size: Float, colour: Int, bold: Boolean) =
        TextView(this).apply {
            text = value
            setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
            setTextColor(colour)
            if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
            setPadding(0, 0, 0, 32)
        }
}
