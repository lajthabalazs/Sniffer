package hu.edudroid.sniffer;

import hu.edudroid.tcp_utils.TCPIPUtils;

import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class IPPacket implements BytePacket {
	private static final byte TCP = 6;
	static final byte UDP = 17;
	private static final int MIN_IP_HEADER_SIZE = 20;

	public short version;
	public short ihl;
	public byte[] sourceIp = new byte[4];
	public byte[] destIp = new byte[4];
	public byte protocol;
	public boolean hasIpOptions = false;
	public TransportPacket payload;
	public int headerLength;

	public IPPacket(DatagramPacket packet, InetSocketAddress localAddress) {
		protocol = UDP;
		sourceIp = packet.getAddress().getAddress();
		destIp = localAddress.getAddress().getAddress();
		payload = new UDPPacket(this, packet, localAddress);
	}
	
	public IPPacket(ByteBuffer buffer, int packetStart, int lastData) {
		// If there isn't a whole ip header, return
		if (packetStart + MIN_IP_HEADER_SIZE > lastData) {
			throw new IllegalArgumentException("Not enough bytes in stream");
		}
		
		System.arraycopy(buffer.array(), packetStart + 12, sourceIp, 0, 4);
		System.arraycopy(buffer.array(), packetStart + 16, destIp, 0, 4);
		version = (short)((buffer.array()[0] & 0xF0) >> 4);
		ihl = (short)((buffer.array()[0] & 0x0F));
		int packetLength = TCPIPUtils.toIntUnsigned(buffer.array()[packetStart + 2], buffer.array()[packetStart + 3]);
		if (packetStart + packetLength > lastData) {
			throw new IllegalArgumentException("Not enough bytes in stream");
		}
		headerLength = ihl * 4;
		protocol = buffer.array()[packetStart + 9];
		if (protocol == UDP) {
			payload = new UDPPacket(buffer, packetStart + headerLength, lastData);
		} else if (protocol == TCP) {
			payload = new TCPPacket(buffer, packetStart + headerLength, lastData);
		}
	}


	@Override
	public byte[] toBytes() {
		byte[] ret = new byte[getPacketLength()];
		writeBytes(ret, 0);
		return ret;
	}

	@Override
	public int getPacketLength() {
		return headerLength + payload.getPacketLength();
	}

	@Override
	public int getPayloadLength() {
		return payload.getPacketLength();
	}

	@Override
	public void writeBytes(byte[] buffer, int start) {
		int packetLength = getPacketLength();
		buffer[start + 0] = TCPIPUtils.toByte(version, ihl);
		buffer[start + 1] = 0; // DSCP, ECN
		System.arraycopy(TCPIPUtils.toTwoBytes(packetLength), 0, buffer, start + 2, 2); // Total length
		System.arraycopy(TCPIPUtils.toTwoBytes(0), 0, buffer, start + 4, 2); // Identification
		buffer[start + 6] = 0; // Flags, Fragment offset part 1
		buffer[start + 7] = 0; // Flags, Fragment offset part 2
		buffer[start + 8] = 64; // TTL
		buffer[start + 9] = protocol;
		System.arraycopy(TCPIPUtils.toTwoBytes(0), 0, buffer, start + 10, 2); // 0's for Header checksum calculation
		System.arraycopy(sourceIp, 0, buffer, start + 12, 4);
		System.arraycopy(destIp, 0, buffer, start + 16, 4);
		// No options
		System.arraycopy(TCPIPUtils.toTwoBytes(TCPIPUtils.checksum(buffer, 0, headerLength)), 0, buffer, start + 10, 2); // Header checksum
		payload.writeBytes(buffer, headerLength);
	}

	@Override
	public byte[] getPayload() {
		return payload.toBytes();
	}

	@Override
	public void writePayload(byte[] buffer, int start) {
		payload.writeBytes(buffer, start);
	}
	
	@Override
	public String toString() {
		String ret = version + "(" + (protocol == UDP?"UDP":(protocol == TCP?"TCP":protocol)) + ") > " + TCPIPUtils.ipAddressToString(sourceIp, 0) + ":" + payload.sourcePort;
		ret = ret + " -> " + TCPIPUtils.ipAddressToString(destIp, 0) + ":" + payload.destPort;
		ret = ret + " length : " + getPacketLength();
		return ret;
	}

}
