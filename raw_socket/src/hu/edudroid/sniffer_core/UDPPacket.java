 package hu.edudroid.sniffer_core;

import hu.edudroid.tcp_utils.TCPIPUtils;

import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class UDPPacket extends TransportPacket {
	private static final int UDP_HEADER_SIZE = 8;
	
	private byte[] data;
	
	public UDPPacket(IPPacket ipPacket, DatagramPacket packet, InetSocketAddress localAddress) {
		super(ipPacket,packet.getPort(),localAddress.getPort());
		data = new byte[packet.getLength()];
	}

	public UDPPacket(IPPacket ipPacket,ByteBuffer buffer, int startIndex, int endIndex) {
		super(ipPacket,buffer, startIndex, endIndex);
		data = new byte[endIndex-startIndex-UDP_HEADER_SIZE];
		System.arraycopy(buffer.array(), startIndex+UDP_HEADER_SIZE, data, 0, endIndex-startIndex-UDP_HEADER_SIZE);
	}

	@Override
	public byte[] toBytes() {
		byte[] ret = new byte[data.length + UDP_HEADER_SIZE];
		return ret;
		}

	@Override
	public void writeBytes(byte[] buffer, int start) {
		System.arraycopy(TCPIPUtils.toTwoBytes(sourcePort), 0, buffer, start + 0, 2); // Source port
		System.arraycopy(TCPIPUtils.toTwoBytes(destPort), 0, buffer, start + 2, 2); // Destination port
		System.arraycopy(TCPIPUtils.toTwoBytes(data.length + 8), 0, buffer, start + 4, 2); // Data + header length
		System.arraycopy(TCPIPUtils.toTwoBytes(0), 0, buffer, start + 6, 2); // 0's for checksum calculation
		System.arraycopy(data, 0, buffer, start + 8, data.length);
		System.arraycopy(TCPIPUtils.toTwoBytes(checksum(buffer)), 0, buffer, start + 6, 2); // Checksum
	}

	@Override
	public int getPacketLength() {
		return UDP_HEADER_SIZE + data.length;
	}

	@Override
	public int getPayloadLength() {
		return data.length;
	}

	@Override
	public byte[] getPayload() {
		return data;
	}

	@Override
	public void writePayload(byte[] buffer, int start) {
		if (buffer.length > start + data.length) {
			System.arraycopy(data, 0, buffer, start, data.length);
		} else {
			throw new ArrayIndexOutOfBoundsException("Couldn't write data to buffer, not enough space.");
		}
	}
}
