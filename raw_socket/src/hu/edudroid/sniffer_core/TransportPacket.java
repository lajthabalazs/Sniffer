package hu.edudroid.sniffer_core;

import hu.edudroid.tcp_utils.TCPIPUtils;

import java.nio.ByteBuffer;

public abstract class TransportPacket implements BytePacket {
	public int sourcePort; 
	public int destPort;
	private IPPacket ipPacket;

	public TransportPacket(IPPacket ipPacket,ByteBuffer buffer, int startIndex, int packetLength) {
		sourcePort = TCPIPUtils.toIntUnsigned(buffer.array()[startIndex], buffer.array()[startIndex + 1]);
		destPort =  TCPIPUtils.toIntUnsigned(buffer.array()[startIndex + 2], buffer.array()[startIndex + 3]);
		this.ipPacket = ipPacket;
	}

	public TransportPacket(IPPacket ipPacket, int sourcePort, int destPort) {
		this.sourcePort = sourcePort;
		this.destPort = destPort;
		this.ipPacket = ipPacket;
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