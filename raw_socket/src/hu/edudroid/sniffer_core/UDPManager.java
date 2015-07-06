package hu.edudroid.sniffer_core;

import hu.edudroid.tcp_utils.TCPIPUtils;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;

public class UDPManager {
	public HashMap<Long, HashMap<Integer,DatagramSocket>> sockets = new HashMap<Long, HashMap<Integer, DatagramSocket>>();
	HashMap<DatagramSocket, UDPListeningThread> threads = new HashMap<DatagramSocket, UDPListeningThread>();

	public void sendPacket(byte[] destAddress, int destPort, int sourcePort, byte[] data) throws IOException {
		long targetAddress = TCPIPUtils.getLongFromAddress(destAddress, destPort);
		System.out.println("Target address " + targetAddress);
		System.out.println("Source port " + sourcePort);
		HashMap<Integer, DatagramSocket> socketArray = sockets.get(targetAddress);
		if (socketArray == null) {
			socketArray = new HashMap<Integer, DatagramSocket>();
			sockets.put(targetAddress, socketArray);
		}
		DatagramSocket socket = socketArray.get(sourcePort);
		if (socket == null) {
			System.out.println("Opening UDP port");
			socket = new DatagramSocket(sourcePort);
			socket.connect(InetAddress.getByAddress(destAddress), destPort);
			UDPListeningThread thread = new UDPListeningThread(socket, this);
			threads.put(socket, thread);
			socketArray.put(sourcePort, socket);
			thread.start();
		}

		System.out.println("Sending data " + data.length);
		socket.send(new DatagramPacket(data, data.length));
	}
	
	public void packetReceived(DatagramPacket packet, InetSocketAddress localAddress) {
	}
}