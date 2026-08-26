package `in`.drishti.shield.ui

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Views are built in Kotlin rather than XML.
 *
 * Not a style preference: it keeps the app free of AppCompat and of a resource
 * indirection, so what a screen looks like can be read in one function. It also makes
 * the projector-legibility constants ([TITLE], [HUGE]) literal numbers in one file
 * instead of scattered across layout files.
 */
object Ui {
    const val BG = 0xFF0B0F14.toInt()
    const val SURFACE = 0xFF141A22.toInt()
    const val INK = 0xFFE8EEF6.toInt()
    const val MUTED = 0xFF8A9AAE.toInt()
    const val ACCENT = 0xFF3FA7FF.toInt()
    const val CRITICAL = 0xFFD62828.toInt()
    const val HIGH = 0xFFE8590C.toInt()
    const val MEDIUM = 0xFFE0A800.toInt()
    const val LOW = 0xFF2E9E5B.toInt()

    // Type scale, tuned for a judge three metres from a washed-out projector.
    const val HUGE = 64f
    const val TITLE = 30f
    const val BODY = 16f
    const val SMALL = 13f
    const val MONO = 12f

    fun Context.dp(value: Int): Int = TypedValue.applyDimension(
        TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics
    ).toInt()

    fun column(context: Context, pad: Int = 20): LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        val p = with(Ui) { context.dp(pad) }
        setPadding(p, p, p, p)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
    }

    fun row(context: Context): LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.HORIZONTAL
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
    }

    fun text(
        context: Context,
        value: CharSequence,
        size: Float = BODY,
        color: Int = INK,
        bold: Boolean = false,
        mono: Boolean = false,
        topMargin: Int = 0,
    ): TextView = TextView(context).apply {
        text = value
        setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
        setTextColor(color)
        if (mono) typeface = Typeface.MONOSPACE
        if (bold) setTypeface(typeface, Typeface.BOLD)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            if (topMargin > 0) this.topMargin = with(Ui) { context.dp(topMargin) }
        }
    }

    fun card(context: Context, accent: Int = SURFACE): LinearLayout =
        LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            background = GradientDrawable().apply {
                setColor(SURFACE)
                cornerRadius = with(Ui) { context.dp(14) }.toFloat()
                setStroke(with(Ui) { context.dp(1) }, accent)
            }
            val p = with(Ui) { context.dp(16) }
            setPadding(p, p, p, p)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                topMargin = with(Ui) { context.dp(12) }
            }
        }

    fun button(
        context: Context,
        label: String,
        fill: Int = SURFACE,
        ink: Int = INK,
        onClick: (View) -> Unit,
    ): Button = Button(context).apply {
        text = label
        isAllCaps = false
        setTextSize(TypedValue.COMPLEX_UNIT_SP, BODY)
        setTextColor(ink)
        gravity = Gravity.CENTER
        background = GradientDrawable().apply {
            setColor(fill)
            cornerRadius = with(Ui) { context.dp(12) }.toFloat()
            setStroke(with(Ui) { context.dp(1) }, Color.argb(60, 255, 255, 255))
        }
        setOnClickListener(onClick)
        layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply {
            val m = with(Ui) { context.dp(4) }
            setMargins(m, with(Ui) { context.dp(10) }, m, 0)
        }
    }

    fun pill(context: Context, label: String, color: Int): TextView = TextView(context).apply {
        text = "  $label  "
        setTextSize(TypedValue.COMPLEX_UNIT_SP, SMALL)
        setTextColor(BG)
        setTypeface(typeface, Typeface.BOLD)
        background = GradientDrawable().apply {
            setColor(color)
            cornerRadius = with(Ui) { context.dp(8) }.toFloat()
        }
        val p = with(Ui) { context.dp(6) }
        setPadding(p, p / 2, p, p / 2)
        layoutParams = LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply {
            rightMargin = with(Ui) { context.dp(8) }
        }
    }

    fun bandColor(band: String): Int = when (band.uppercase()) {
        "CRITICAL" -> CRITICAL
        "HIGH" -> HIGH
        "MEDIUM" -> MEDIUM
        "LOW" -> LOW
        else -> MUTED
    }
}
