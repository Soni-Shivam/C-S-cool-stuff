package in.drishti.fixture.bank

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "INERT BANKING FIXTURE\n\nNo login, account, network, storage, or user-data behavior exists."
            textSize = 20f
            setPadding(48, 48, 48, 48)
        })
    }
}
