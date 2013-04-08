package hu.edudroid.sniffer;

import java.nio.ByteBuffer;

public class Packet {
	public byte[] sourceIp = new byte[4];
	public int sourcePort; 
	public byte[] destIp = new byte[4];
	public byte protocol;
	public int destPort;
	
	public boolean parse(ByteBuffer buffer, int packetStart) {
		System.arraycopy(buffer.array(), packetStart + 12, sourceIp, 0, 4);
		System.arraycopy(buffer.array(), packetStart + 16, destIp, 0, 4);
		protocol = buffer.array()[packetStart + 9];
		return true;
	}
}
