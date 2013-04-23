 package hu.edudroid.sniffer;

import hu.edudroid.tcp_utils.TCPIPUtils;

import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class UDPPacket extends TransportPacket {
	private static final int UDP_HEADER_SIZE = 8;

	private IPPacket ipPacket;
	private byte[] data;

	public UDPPacket(IPPacket ipPacket, DatagramPacket packet, InetSocketAddress localAddress) {
		super(packet.getPort(),localAddress.getPort());
		this.ipPacket = ipPacket;
		data = new byte[packet.getLength()];
	}

	public UDPPacket(ByteBuffer buffer, int startIndex, int endIndex) {
		super(buffer, startIndex, endIndex);
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
		System.arraycopy(data, 0, buffer, 8, data.length);
		System.arraycopy(TCPIPUtils.toTwoBytes(checksum(buffer)), 0, buffer, 26, 2); // Checksum
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

	public int checksum(byte[] ret) {
		int sum = 0;
		int length = ret.length;
		int i = 0;
		int carry = 0;
		
		while(length > 1){
	    	//Calculating the sum of byte pairs
	    	sum += (((ret[i] << 8) & 0xFF00) | ((ret[i+1]) & 0xFF));
	    	i += 2;
	    	length -= 2;
	    }
		//if length is odd, use padding with 0's from right
		if(length > 0){
			sum += (ret[i] << 8 & 0xFF00);
		}
		carry = (0xFFFF0000 & sum) >> 16; //Carry
	    if(carry > 0){
	    	sum = sum & 0xFFFF;
	    	sum += carry;
	    }
	    		
		//Pseudo header
		sum += (((ipPacket.sourceIp[0] << 8) & 0xFF00) | ((ipPacket.sourceIp[1]) & 0xFF));
		sum += (((ipPacket.sourceIp[2] << 8) & 0xFF00) | ((ipPacket.sourceIp[3]) & 0xFF));
		sum += (((ipPacket.destIp[0] << 8) & 0xFF00) | ((ipPacket.destIp[1]) & 0xFF));
		sum += (((ipPacket.destIp[2] << 8) & 0xFF00) | ((ipPacket.destIp[3]) & 0xFF));
		sum += (0x00FF & IPPacket.UDP);
		sum += (0xFFFF & ret.length);
		carry = (0xFFFF0000 & sum) >> 16; //Carry
	    if(carry > 0){
	    	sum = sum & 0xFFFF;
	    	sum += carry;
	    }
		
	    return (~sum) & 0xFFFF;
	}
}
