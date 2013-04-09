package hu.edudroid.sniffer;

import java.nio.ByteBuffer;

public class Packet {
	private static final byte TCP = 6;
	private static final byte UDP = 17;
	public byte[] sourceIp = new byte[4];
	public int sourcePort; 
	public byte[] destIp = new byte[4];
	public byte protocol;
	public int destPort;
	public int packetLength;
	public int ipPayloadOffset;
	public boolean hasIpOptions = false;
	public ByteBuffer data = ByteBuffer.allocate(32000);
	public short version;
	public short ihl;
	public int dataOffset;
	
	public boolean parse(ByteBuffer buffer, int packetStart) {
		System.arraycopy(buffer.array(), packetStart + 12, sourceIp, 0, 4);
		System.arraycopy(buffer.array(), packetStart + 16, destIp, 0, 4);
		version = (short)((buffer.array()[0] & 0xF0) >> 4);
		ihl = (short)((buffer.array()[0] & 0x0F));
		packetLength = TCPIPUtils.toIntUnsigned(buffer.array()[packetStart + 2], buffer.array()[packetStart + 3]);
		System.out.println("Length : " + packetLength + " (" + buffer.array()[packetStart + 2] + " " + buffer.array()[packetStart + 3] + ")");
		ipPayloadOffset = ihl * 4;
		System.out.println("Payload offset : " + ipPayloadOffset);
		sourcePort = TCPIPUtils.toIntUnsigned(buffer.array()[packetStart + ipPayloadOffset + 1], buffer.array()[packetStart + ipPayloadOffset]);
		System.out.println("SourcePort : " + sourcePort + " (" + buffer.array()[packetStart + ipPayloadOffset] + " " + buffer.array()[packetStart + ipPayloadOffset + 1] + ")");
		destPort =  TCPIPUtils.toIntUnsigned(buffer.array()[packetStart + ipPayloadOffset + 2], buffer.array()[packetStart + ipPayloadOffset + 3]);
		System.out.println("DestPort : " + destPort + " (" + buffer.array()[packetStart + ipPayloadOffset + 2] + " " + buffer.array()[packetStart + ipPayloadOffset + 3] + ")");
		protocol = buffer.array()[packetStart + 9];
		if (protocol == UDP) {
			dataOffset = ipPayloadOffset + 8;
			System.arraycopy(buffer.array(), packetStart + dataOffset, data.array(), 0, packetLength);
		} else if (protocol == TCP) {
			ipPayloadOffset = TCPIPUtils.toIntUnsigned(buffer.array()[packetStart + 40], buffer.array()[packetStart + 41]);
			System.arraycopy(buffer.array(), packetStart + ipPayloadOffset , data.array(), 0, packetLength);
		}
		
		return true;
	}
	
	@Override
	public String toString() {
		String ret = version + "(" + (protocol == UDP?"UDP":(protocol == TCP?"TCP":protocol)) + ") > " + TCPIPUtils.ipAddressToString(sourceIp, 0) + ":" + sourcePort;
		ret = ret + " -> " + TCPIPUtils.ipAddressToString(destIp, 0) + ":" + destPort;
		ret = ret + " length : " + packetLength;
		return ret;
	}
}
