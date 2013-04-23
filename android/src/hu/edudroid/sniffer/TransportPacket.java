package hu.edudroid.sniffer;

import hu.edudroid.tcp_utils.TCPIPUtils;

import java.nio.ByteBuffer;

public abstract class TransportPacket implements BytePacket {
	public int sourcePort; 
	public int destPort;

	public TransportPacket(ByteBuffer buffer, int startIndex, int packetLength) {
		sourcePort = TCPIPUtils.toIntUnsigned(buffer.array()[startIndex], buffer.array()[startIndex + 1]);
		destPort =  TCPIPUtils.toIntUnsigned(buffer.array()[startIndex + 2], buffer.array()[startIndex + 3]);		
	}

	public TransportPacket(int sourcePort, int destPort) {
		this.sourcePort = sourcePort;
		this.destPort = destPort;
	}
}