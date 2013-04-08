package hu.edudroid.sniffer;

import java.nio.ByteBuffer;

public class Packet {
	public byte[] sourceIp;
	public int sourcePort; 
	public byte[] destIp;
	public int destPort;
	
	public boolean parse(ByteBuffer buffer, int packetStart) {
		return false;
	}
}
