package `in`.drishti.shield.ui

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.FrameLayout
import android.widget.ImageView
import `in`.drishti.shield.R
import `in`.drishti.shield.ui.Ui.dp

/**
 * The DRISHTI mark, breathing.
 *
 * Deliberately **not** a spinner. A spinner says "the machine is busy" and every user
 * has learned to stop reading the screen when one appears. A slow breath says "someone
 * is looking at this", which is the feeling the interstitial exists to create — the
 * user has not been told anything is wrong yet, and must not be alarmed by the wait.
 *
 * Two things move, on the same cycle so they read as one object:
 *
 *  * the mark scales between [MIN_SCALE] and [MAX_SCALE] — about six percent, small
 *    enough that nobody consciously sees the size change;
 *  * a radial glow behind it swells and fades a beat wider than the mark does.
 *
 * [BREATH_MS] is one half-cycle, so a full inhale-exhale is twice that. It is set near
 * a calm human breath rate on purpose; faster reads as urgency, and urgency here would
 * pre-empt a verdict that has not been reached yet.
 */
class BreathingLogoView(context: Context) : FrameLayout(context) {

    private val glow = View(context)
    private val mark = ImageView(context)
    private var animator: ValueAnimator? = null

    init {
        val size = context.dp(GLOW_DP)
        glow.background = GradientDrawable(
            GradientDrawable.Orientation.TOP_BOTTOM,
            intArrayOf(GLOW_CORE, GLOW_MID, GLOW_EDGE),
        ).apply {
            gradientType = GradientDrawable.RADIAL_GRADIENT
            gradientRadius = size / 2f
            shape = GradientDrawable.OVAL
        }
        addView(
            glow,
            LayoutParams(size, size, Gravity.CENTER),
        )

        mark.setImageResource(R.drawable.ic_drishti_eye)
        addView(
            mark,
            LayoutParams(context.dp(MARK_DP), context.dp(MARK_DP), Gravity.CENTER),
        )

        layoutParams = LayoutParams(MATCH_PARENT, context.dp(GLOW_DP))
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        start()
    }

    override fun onDetachedFromWindow() {
        animator?.cancel()
        animator = null
        super.onDetachedFromWindow()
    }

    private fun start() {
        if (animator != null) return
        animator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = BREATH_MS
            repeatCount = ValueAnimator.INFINITE
            repeatMode = ValueAnimator.REVERSE
            interpolator = AccelerateDecelerateInterpolator()
            addUpdateListener { a ->
                val t = a.animatedValue as Float
                val scale = MIN_SCALE + (MAX_SCALE - MIN_SCALE) * t
                mark.scaleX = scale
                mark.scaleY = scale
                glow.scaleX = GLOW_MIN_SCALE + (GLOW_MAX_SCALE - GLOW_MIN_SCALE) * t
                glow.scaleY = glow.scaleX
                glow.alpha = GLOW_MIN_ALPHA + (GLOW_MAX_ALPHA - GLOW_MIN_ALPHA) * t
            }
            start()
        }
    }

    private companion object {
        /** One half-breath. A full inhale-exhale is twice this. */
        const val BREATH_MS = 1_600L

        const val MIN_SCALE = 0.94f
        const val MAX_SCALE = 1.00f
        const val GLOW_MIN_SCALE = 0.88f
        const val GLOW_MAX_SCALE = 1.08f
        const val GLOW_MIN_ALPHA = 0.30f
        const val GLOW_MAX_ALPHA = 0.85f

        const val MARK_DP = 168
        const val GLOW_DP = 320

        /** The brand purple, faded to nothing at the edge of the oval. */
        val GLOW_CORE = 0x807C3AED.toInt()
        val GLOW_MID = 0x2E7C3AED
        val GLOW_EDGE = 0x007C3AED
    }
}
