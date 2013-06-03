package hu.edudroid.sniffer;

import hu.edudroid.tcp_utils.TCPIPUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.HashMap;

import android.util.SparseArray;

public class TCPManager {
	public HashMap<Long, SparseArray<Socket>> sockets = new HashMap<Long, SparseArray<Socket>>();
	HashMap<Socket, TCPListeningThread> threads = new HashMap<Socket, TCPListeningThread>();
	HashMap<Long, long[]> tcpnumbers = new HashMap<Long, long[]>();
	
	
	private MyVpnService vpnService;
	
	public TCPManager(MyVpnService vpnService) {
		this.vpnService = vpnService;
	}

	public void sendPacket(IPPacket packet) throws IOException {
		byte[] destAddress = packet.destIp;
		byte[] sourceAddress = packet.sourceIp;
		int destPort = packet.payload.destPort; 
		int sourcePort = packet.payload.sourcePort; 
		byte[] data = packet.payload.getPayload();
		long targetAddress = TCPIPUtils.getLongFromAddress(destAddress, destPort);
		System.out.println("Target address " + targetAddress);
		System.out.println("Source port " + sourcePort);
		
		SparseArray<Socket> socketArray = sockets.get(targetAddress);
		if (socketArray == null) {
			socketArray = new SparseArray<Socket>();
			sockets.put(targetAddress, socketArray);
		}
		
		long[] numbers = tcpnumbers.get(targetAddress);
		if (numbers == null) {
			numbers = new long[]{0,packet.payload.getTCPNumbers()[1]};
			tcpnumbers.put(targetAddress, numbers);
			
		}
		
		Socket socket = socketArray.get(sourcePort);
		if (socket == null) {
			System.out.println("Opening TCP port");
			socket = new Socket(InetAddress.getByAddress(destAddress),destPort, null, sourcePort);
			vpnService.protect(socket);
			
			//after socket opened send back empty syn,ack TCP packet
			TCPPacket synack = new TCPPacket(null,destPort,sourcePort);
			synack.setSequenceNumber(numbers[0]);
			synack.setAcknowledgementNumber(numbers[1]+1);
			vpnService.packetReceived(synack, InetAddress.getByAddress(sourceAddress), InetAddress.getByAddress(destAddress));
			TCPListeningThread thread = new TCPListeningThread(socket, this);
			threads.put(socket, thread);
			socketArray.append(sourcePort, socket);
			thread.start();
		}

		//Send data read from stream through socket
		System.out.println("Sending data " + data.length);
		OutputStream out = socket.getOutputStream();
		out.write(data);		
		//{SequenceNumber,AcknowledgementNumber}
		tcpnumbers.get(targetAddress)[1] = packet.payload.getTCPNumbers()[0];
	}
	
	public void packetReceived(byte[] TCPPayload, InetSocketAddress destAddress, InetSocketAddress sourceAddress) {
		TCPPacket packet = new TCPPacket(TCPPayload, destAddress.getPort(), sourceAddress.getPort());
		
		long targetAddress = TCPIPUtils.getLongFromAddress(destAddress.getAddress().getAddress(), sourceAddress.getPort());
		tcpnumbers.get(targetAddress)[0] += TCPPayload.length;
		packet.setSequenceNumber(tcpnumbers.get(targetAddress)[0]);
		packet.setAcknowledgementNumber(tcpnumbers.get(targetAddress)[1]);
		
		vpnService.packetReceived(packet, destAddress.getAddress(), sourceAddress.getAddress());
	}
}