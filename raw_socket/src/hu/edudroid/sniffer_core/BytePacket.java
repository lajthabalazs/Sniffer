package hu.edudroid.sniffer_core;

public interface BytePacket {
	static final byte ZERO = 0;
	
	public int getPacketLength();
	public int getPayloadLength();

	public byte[] toBytes();
	public void writeBytes(byte[] buffer, int start);
	public byte[] getPayload();
	public void writePayload(byte[] buffer, int start);
}