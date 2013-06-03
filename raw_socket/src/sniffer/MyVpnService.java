package hu.edudroid.sniffer;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

public class MyVpnService extends VpnService implements Runnable {

	private boolean running = false;
	private Thread thread;
	private ParcelFileDescriptor localInterface;
	private ByteBuffer buffer = ByteBuffer.allocate(32767);
	private UDPManager udpManager = new UDPManager(this);
	private TCPManager tcpManager = new TCPManager(this);

	private FileInputStream localMessageReader;

	private FileOutputStream localMessageWriter;


	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
		Builder builder = new Builder();
		builder.setSession("Sniffer");
		builder.setMtu(1450);
		builder.addAddress("10.0.0.2", 32);
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
		try {
			running = true;		
			localMessageReader = new FileInputStream(localInterface.getFileDescriptor());
			localMessageWriter = new FileOutputStream(localInterface.getFileDescriptor());
		} catch(Exception e) {
			e.printStackTrace();
			return;
		}
		int bufferEnd = 0;
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
				Log.e("Packet", "Read bytes " + readBytes);
				bufferEnd = readBytes;
				IPPacket packet = null;
				// Reads available packets
				while (true) {
					try {
						packet = new IPPacket(buffer, 0, bufferEnd);
					} catch (IllegalArgumentException e) {
						// If there is an error reading a packet, everything is screwed, restart the VPN
					}
					if(packet != null) {
						Log.e("Packet", packet.toString());
						if (packet.protocol == IPPacket.UDP) {
							try {
								udpManager.sendPacket(packet.destIp, packet.payload.destPort, packet.payload.sourcePort, packet.payload.getPayload());
							} catch (IOException e) {
								e.printStackTrace();
							}
						}
						else if (packet.protocol == IPPacket.TCP) {
							try {
								tcpManager.sendPacket(packet);
								buffer.compact();
							} catch (IOException e) {
								Log.e("MyVPnService", e.getMessage());
							}
						}
						// Shift buffer
						buffer.compact();
						packet = null;
					} else {
						System.out.println("Not a good packet");
					}
				}
			}
		}
		try {
			localMessageReader.close();
		} catch (IOException e) {
			Log.e("MyVPnService", e.getMessage());
		}
		try {
			localMessageWriter.close();
		} catch (IOException e) {
			Log.e("MyVPnService", e.getMessage());
		}
	}

	public void packetReceived(DatagramPacket packet, InetSocketAddress localAddress) {
		synchronized (localMessageWriter) {
			// Construct packet
			IPPacket serializer = new IPPacket(packet, localAddress);
			try {
				localMessageWriter.write(serializer.toBytes());
			} catch (IOException e) {
				Log.e("MyVPnService", e.getMessage());
			}
		}
	}

	public void packetReceived(TCPPacket packet, InetAddress destAddress, InetAddress sourceAddress) {
		synchronized (localMessageWriter) {
			try {
				IPPacket serializer = new IPPacket(packet, destAddress, sourceAddress);
				localMessageWriter.write(serializer.toBytes());
			} catch (IOException e) {
				Log.e("MyVPnService", e.getMessage());
			}
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
