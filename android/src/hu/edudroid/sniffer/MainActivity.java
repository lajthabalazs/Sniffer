package hu.edudroid.sniffer;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Toast;

public class MainActivity extends Activity implements OnClickListener {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		findViewById(R.id.startButton).setOnClickListener(this);
	}

	@Override
	public void onClick(View v) {
		Intent intent = VpnService.prepare(this);
		if (intent != null) {
			startActivityForResult(intent, 0);
		} else {
			onActivityResult(0, RESULT_OK, null);
		}
	}

	@Override
	protected void onActivityResult(int request, int result, Intent data) {
		if (result == RESULT_OK) {
			Intent intent = new Intent(this, MyVpnService.class);
			startService(intent);
		} else {
			Toast.makeText(this, "Unable to start service", Toast.LENGTH_LONG).show();
		}
	}
}
