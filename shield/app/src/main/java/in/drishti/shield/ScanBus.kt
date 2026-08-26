package `in`.drishti.shield

import android.os.Handler
import android.os.Looper
import java.util.concurrent.CopyOnWriteArrayList

/**
 * In-process pub/sub between [WatchService] and the screens.
 *
 * The watcher and the UI live in the same process, so a broadcast round-trip through
 * the system would add latency to the one number the demo puts on screen. This is a
 * plain observable holding the current scan; listeners are always called on the main
 * thread so a screen never has to post its own update.
 */
object ScanBus {
    private val listeners = CopyOnWriteArrayList<(Scan) -> Unit>()
    private val main = Handler(Looper.getMainLooper())

    /**
     * The **newest** scan, by the instant its file landed — not simply the last one
     * published.
     *
     * The distinction is not academic. Each scan publishes twice: once when the block
     * decision lands, and again ~10 s later when the composite score arrives. Two
     * deliveries eight seconds apart therefore interleave, and the older scan's score
     * update was arriving *after* the newer scan's verdict. `current` went backwards,
     * and the verdict screen jumped from the app it had just blocked back to the one
     * it had cleared — on stage, in the middle of the beat that matters.
     */
    @Volatile
    var current: Scan? = null
        private set

    /** Every scan this session, newest last. Bounded — the demo is not a server. */
    private val historyList = CopyOnWriteArrayList<Scan>()
    val history: List<Scan> get() = historyList.toList()

    fun publish(scan: Scan) {
        val showing = current
        if (showing == null || scan.id == showing.id || scan.detectedAtMs >= showing.detectedAtMs) {
            current = scan
        }
        val index = historyList.indexOfFirst { it.id == scan.id }
        if (index >= 0) historyList[index] = scan else historyList.add(scan)
        while (historyList.size > 25) historyList.removeAt(0)
        main.post { listeners.forEach { it(scan) } }
    }

    fun subscribe(listener: (Scan) -> Unit) {
        listeners.add(listener)
        current?.let { snapshot -> main.post { listener(snapshot) } }
    }

    fun unsubscribe(listener: (Scan) -> Unit) {
        listeners.remove(listener)
    }

    fun find(id: String): Scan? = historyList.firstOrNull { it.id == id }
}
