package `in`.drishti.benign.sanchay

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * The only screen: a month of spending, rendered from a hardcoded array.
 *
 * It looks like the app it claims to be, because on stage this one actually gets
 * installed and someone may well open it. The disclosure at the bottom is what stops
 * that from being a lie — the same rule the rest of DRISHTI follows, that a screen
 * says what it is rather than trusting the audience to remember.
 */
class MainActivity : Activity() {

    private val rows = listOf(
        Triple("Big Bazaar", "Groceries", "-1,240"),
        Triple("HP Petrol Pump", "Fuel", "-2,000"),
        Triple("Monthly rent", "Rent", "-18,500"),
        Triple("MSEB bill", "Utilities", "-1,865"),
        Triple("Auto — Kothrud", "Transport", "-140"),
        Triple("Salary credit", "Income", "+68,400"),
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        InertMarker.noop("MainActivity.onCreate")

        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#F6F7F9"))
            setPadding(48, 80, 48, 48)
        }

        page.addView(label("Sanchay", 26f, Color.parseColor("#0F6E4F"), true))
        page.addView(label("Expenses · August", 15f, Color.parseColor("#6B7280"), false))

        val summary = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.WHITE)
            setPadding(40, 40, 40, 40)
        }
        summary.addView(label("Spent this month", 13f, Color.parseColor("#6B7280"), false))
        summary.addView(label("Rs 23,745", 34f, Color.parseColor("#111827"), true))
        summary.addView(
            label("of Rs 30,000 budget · 6 transactions read from bank SMS", 13f,
                Color.parseColor("#6B7280"), false)
        )
        page.addView(summary)

        page.addView(label("Recent", 15f, Color.parseColor("#111827"), true))
        rows.forEach { (payee, category, amount) ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setBackgroundColor(Color.WHITE)
                setPadding(40, 28, 40, 28)
            }
            val left = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f)
            }
            left.addView(label(payee, 16f, Color.parseColor("#111827"), false))
            left.addView(label(category, 13f, Color.parseColor("#6B7280"), false))
            row.addView(left)
            row.addView(
                label(amount, 16f, if (amount.startsWith("+")) Color.parseColor("#0F6E4F")
                else Color.parseColor("#111827"), true).apply {
                    gravity = Gravity.END
                    layoutParams = LinearLayout.LayoutParams(WRAP, WRAP)
                }
            )
            page.addView(row)
        }

        val disclosure = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#EEF2F7"))
            setPadding(40, 40, 40, 40)
        }
        disclosure.addView(label("DRISHTI CONTROL SAMPLE", 13f, Color.parseColor("#0F6E4F"), true))
        disclosure.addView(
            label(
                "This app was authored by the DRISHTI project as the negative control " +
                    "for its demo. It declares READ_SMS, READ_CONTACTS, " +
                    "QUERY_ALL_PACKAGES and SYSTEM_ALERT_WINDOW — the same privileged " +
                    "surface a caller-ID app holds — and it contains no code that uses " +
                    "any of them. The figures above are a hardcoded array.\n\n" +
                    "It exists so the demo can show what DRISHTI does with an app it " +
                    "does not block.",
                13f, Color.parseColor("#4B5563"), false,
            )
        )
        page.addView(disclosure)

        setContentView(ScrollView(this).apply { addView(page) })
    }

    private fun label(value: String, size: Float, colour: Int, bold: Boolean) =
        TextView(this).apply {
            text = value
            setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
            setTextColor(colour)
            if (bold) setTypeface(typeface, Typeface.BOLD)
            setPadding(0, 0, 0, 18)
        }

    private companion object {
        const val WRAP = LinearLayout.LayoutParams.WRAP_CONTENT
    }
}
