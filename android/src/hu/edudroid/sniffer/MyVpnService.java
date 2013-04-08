package hu.edudroid.sniffer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.nio.ByteBuffer;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

public class MyVpnService extends VpnService implements Runnable {
	
	private static final int MAX_PACKET_SIZE = 2000;
	
	private boolean running = false;
	private Thread thread;
	private ParcelFileDescriptor localInterface;
	private ByteBuffer buffer = ByteBuffer.allocate(32767);
	private Packet packet = new Packet();
	
	
	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
		Builder builder = new Builder();
		builder.setSession("Sniffer");
		builder.setMtu(1450);
		builder.addAddress("152.66.244.50",24);
		//builder.addRoute("152.66.244.50",24);
		//builder.addDnsServer("123.123.123.123");
		//builder.addSearchDomain("123.123.123.123");
		localInterface = builder.establish();
		thread = new Thread(this, "SnifferVPN");
		thread.start();
		return START_STICKY;
	}

	@Override
	public void run() {
		running = true;
		FileInputStream localMessageReader = new FileInputStream(localInterface.getFileDescriptor());
		FileOutputStream localMessageWriter = new FileOutputStream(localInterface.getFileDescriptor());
		int packetStart = 0;
		int bufferEnd = 0;
		final int bufferSize = buffer.limit();
		while(running){
			int readBytes = 0;
			try {
				readBytes = localMessageReader.read(buffer.array());
				Log.e("Read bytes", "Mizu " + readBytes);
			} catch (IOException e) {
				e.printStackTrace();
				continue;
			}
			if (readBytes > 0) {
				bufferEnd += readBytes;
				// Checks if there is a message in the packet array
				int packetLength = TCPIPUtils.getPacketLength(buffer, packetStart, bufferEnd);
				if (packetLength != -1) {
					// Check if there is a whole packet in there
					if (packetLength < bufferEnd - packetStart) {
						// We have a packet, let's process it!
						if(packet.parse(buffer, packetStart)) {
							// TODO send packet
							Log.e("A packet was intercepted", "" + packetLength);
							// Check if buffer should be shifted
							if (bufferSize - bufferEnd < MAX_PACKET_SIZE) {
								bufferEnd -= packetStart;
								packetStart = 0;
								buffer.compact();
							}
						}
					}
				}
			}
		}
		try {
			localMessageReader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			localMessageWriter.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	@Override
	public void onDestroy() {
		running = false;
		if (thread != null) {
			thread.interrupt();
		}
		super.onDestroy();
	}
}
