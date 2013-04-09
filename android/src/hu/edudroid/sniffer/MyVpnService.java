package hu.edudroid.sniffer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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
		builder.addAddress("10.0.0.1", 32);
		builder.addRoute("0.0.0.0", 0);
		builder.addDnsServer("8.8.8.8");
		builder.addSearchDomain("tmit.bme.hu");
		localInterface = builder.establish();
		thread = new Thread(this, "SnifferVPN");
		thread.start();
		return START_STICKY;
	}

	@Override
	public void run() {
		FileInputStream localMessageReader;
		FileOutputStream localMessageWriter;
		try {
			running = true;		
			localMessageReader = new FileInputStream(localInterface.getFileDescriptor());
			localMessageWriter = new FileOutputStream(localInterface.getFileDescriptor());
		} catch(Exception e) {
			e.printStackTrace();
			return;
		}
		int packetStart = 0;
		int bufferEnd = 0;
		final int bufferSize = buffer.limit();
		int packetLength;
		int readBytes;
		while(running){
			try {
				Thread.sleep(20);
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
			readBytes = 0;
			try {
				readBytes = localMessageReader.read(buffer.array());
			} catch (IOException e) {
				Log.e("MyVPnService", e.getMessage());
				continue;
			}
			if (readBytes > 0) {
				bufferEnd += readBytes;
				// Checks if there is a message in the packet array
				packetLength = TCPIPUtils.getPacketLength(buffer, packetStart, bufferEnd);
				if (packetLength != -1) {
					// Check if there is a whole packet in there
					if (packetLength < bufferEnd - packetStart) {
						// We have a packet, let's process it!
						if(packet.parse(buffer, packetStart)) {
							Log.e("Packet", packet.toString());
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
