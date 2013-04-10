package hu.edudroid.sniffer;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.HashMap;

import android.util.SparseArray;

public class UDPManager {
	public HashMap<Long, SparseArray<DatagramSocket>> sockets = new HashMap<Long, SparseArray<DatagramSocket>>();
	HashMap<DatagramSocket, UDPListeningThread> threads = new HashMap<DatagramSocket, UDPListeningThread>();
	private MyVpnService vpnService;
	
	public UDPManager(MyVpnService vpnService) {
		this.vpnService = vpnService;
	}

	public void sendPacket(byte[] destAddress, int destPort, int sourcePort, byte[] data) throws IOException {
		long targetAddress = TCPIPUtils.getLongFromAddress(destAddress, destPort);
		System.out.println("Opening UDP port");
		System.out.println("Target address " + targetAddress);
		System.out.println("Source port " + sourcePort);
		SparseArray<DatagramSocket> socketArray = sockets.get(targetAddress);
		if (socketArray == null) {
			socketArray = new SparseArray<DatagramSocket>();
			sockets.put(targetAddress, socketArray);
		}
		DatagramSocket socket = socketArray.get(sourcePort);
		if (socket == null) {
			socket = new DatagramSocket(sourcePort);
			vpnService.protect(socket);
			socket.connect(InetAddress.getByAddress(destAddress), destPort);
			UDPListeningThread thread = new UDPListeningThread(socket);
			threads.put(socket, thread);
			socketArray.append(sourcePort, socket);
			thread.start();
		}
		socket.send(new DatagramPacket(data, data.length));
	}
}