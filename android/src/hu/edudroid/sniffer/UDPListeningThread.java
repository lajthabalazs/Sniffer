package hu.edudroid.sniffer;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

import android.util.Log;

public class UDPListeningThread implements Runnable{
	
	byte[] receivingBuffer = new byte[2048];
	DatagramPacket receivePacket = new DatagramPacket(receivingBuffer, 2048);
	private DatagramSocket socket;
	private boolean running;
	private Thread thread;
	private UDPManager manager;

	public UDPListeningThread(DatagramSocket socket, UDPManager manager) {
		this.socket = socket;
		this.manager = manager;
	}

	public void start(){
		running = true;
		thread = new Thread(this);
		thread.start();
	}
	
	@Override
	public void run() {
		
		while(running) {
			System.out.println("Listening on " + socket.getLocalAddress());
			System.out.println("Remote " + socket.getRemoteSocketAddress());
			try {
				socket.receive(receivePacket);
				System.out.println("Packet received from " + socket.getRemoteSocketAddress().toString() + " bytes " + receivePacket.getLength());
				
			} catch (IOException e) {
				Log.e("Error receiving packet", "From " + socket.getRemoteSocketAddress() + " > " + e.toString());
			}
		}
	}
}
