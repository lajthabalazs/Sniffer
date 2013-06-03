package hu.edudroid.sniffer;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;

import android.util.Log;

public class TCPListeningThread implements Runnable{
	private Socket socket;
	private boolean running;
	private Thread thread;
	private TCPManager manager;
	private ByteBuffer buffer = ByteBuffer.allocate(32767);
	
	private static final int MAX_PACKET_SIZE = 2000;

	public TCPListeningThread(Socket listener, TCPManager manager) {
		this.manager = manager;
	}

	public void start(){
		running = true;
		thread = new Thread(this);
		thread.start();
	}

	@Override
	public void run() {
		int bufferEnd = 0;
		final int bufferSize = buffer.limit();
		int readBytes;
		InputStream input = null;
		try {
			System.out.println("Listening on " + socket.getLocalPort());
			input = socket.getInputStream();
		} catch (IOException e) {
			Log.e("Error reading from TCP stream", e.toString());
		}
		while(running) {
			try {
				Thread.sleep(20);
			} catch (InterruptedException e1) {
				Log.e("MyVPnService TCP", e1.getMessage());
			}
			readBytes = 0;
			try {
				readBytes = input.read(buffer.array());
			} catch (IOException e) {
				Log.e("MyVPnService TCP", e.getMessage());
				continue;
			}
			if (readBytes > 0) {
				Log.e("Packet", "Read bytes " + readBytes);
				bufferEnd += readBytes;
				try {
					if(bufferEnd <= 32767){
						byte[] array = new byte[bufferEnd];
						System.arraycopy(buffer.array(), 0, array, 0, bufferEnd);
						manager.packetReceived(array, new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort()), new InetSocketAddress(socket.getInetAddress(), socket.getPort()));
						
						// Check if buffer should be shifted
						if (bufferSize - bufferEnd < MAX_PACKET_SIZE) {
							bufferEnd -= array.length;
							buffer.compact();
						}
					}
				} catch (IllegalArgumentException e) {
					Log.e("MyVPnService TCP", e.getMessage());
				}
			}
		}
	}
}
