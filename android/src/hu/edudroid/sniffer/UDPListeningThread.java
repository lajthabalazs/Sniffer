package hu.edudroid.sniffer;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

public class UDPListeningThread implements Runnable{
	
	byte[] receivingBuffer = new byte[2048];
	DatagramPacket receivePacket = new DatagramPacket(receivingBuffer, 2048);
	private DatagramSocket socket;
	private boolean running;
	private Thread thread;

	public UDPListeningThread(DatagramSocket socket) {
		this.socket = socket;
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
				System.out.println("Packet received from " + socket.getRemoteSocketAddress().toString());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}
