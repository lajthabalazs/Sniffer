package hu.edudroid.sniffer;

import hu.edudroid.tcp_utils.TCPIPUtils;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;

import android.util.Log;
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
		System.out.println("Target address " + targetAddress);
		System.out.println("Source port " + sourcePort);
		SparseArray<DatagramSocket> socketArray = sockets.get(targetAddress);
		if (socketArray == null) {
			socketArray = new SparseArray<DatagramSocket>();
			sockets.put(targetAddress, socketArray);
		}
		DatagramSocket socket = socketArray.get(sourcePort);
		if (socket == null) {
			System.out.println("Opening UDP port");
			socket = new DatagramSocket(sourcePort);
			vpnService.protect(socket);
			socket.connect(InetAddress.getByAddress(destAddress), destPort);
			Log.e("UDP localAddr",socket.getLocalAddress().toString());
			UDPListeningThread thread = new UDPListeningThread(socket, this);
			threads.put(socket, thread);
			socketArray.append(sourcePort, socket);
			thread.start();
		}

		System.out.println("Sending data " + data.length);
		socket.send(new DatagramPacket(data, data.length));
	}
	
	public void packetReceived(DatagramPacket packet, InetSocketAddress localAddress) {
		vpnService.packetReceived(packet, localAddress);
	}
}