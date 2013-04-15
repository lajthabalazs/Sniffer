package hu.edudroid.sniffer;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends Activity implements OnClickListener {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		findViewById(R.id.startButton).setOnClickListener(this);
		findViewById(R.id.sendUDPPacketButton).setOnClickListener(this);
	}

	@Override
	public void onClick(View v) {
		if(v.getId() == R.id.startButton) {
			Intent intent = VpnService.prepare(this);
			if (intent != null) {
				startActivityForResult(intent, 0);
			} else {
				onActivityResult(0, RESULT_OK, null);
			}
		} else if (v.getId() == R.id.sendUDPPacketButton) {
			Log.e("Sending a probe packet", "Cool");
			final String address = ((EditText)findViewById(R.id.targetAddressEdit)).getText().toString();
			final int port = Integer.parseInt(((EditText)findViewById(R.id.targetPortEdit)).getText().toString());
			Thread thread = new Thread(new Runnable() {
				
				@Override
				public void run() {
					DatagramSocket socket;
					try {
						DatagramPacket packet = new DatagramPacket(new byte[]{(byte)1, (byte)1, (byte)2,(byte)3,(byte)5}, 5);
						socket = new DatagramSocket();
						socket.connect(InetAddress.getByName(address), port);
						Log.e("Sending packet to " + socket.getRemoteSocketAddress().toString(), packet.toString());
						socket.send(packet);
						
						Log.e("Packet sent to " + socket.getRemoteSocketAddress().toString(), packet.toString());
						socket.close();
					} catch (SocketException e) {
						e.printStackTrace();
					} catch (UnknownHostException e) {
						e.printStackTrace();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			});
			thread.start();
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
