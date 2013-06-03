package hu.edudroid.sniffer;

import hu.edudroid.tcp_utils.TCPIPUtils;

public class TCPPacket extends TransportPacket {
	
	//TCP specific
	public boolean URG = false;
	public boolean ACK = false;
	public boolean PSH = false;
	public boolean RST = false;
	public boolean SYN = false;
	public boolean FIN = false;
	public int window;
	public long seqNum; //Sequence Number
	public long ackNum; //Acknowledgement Number
	public int urgPointer;
	private int headerLength;
	private byte[] data;

	public TCPPacket(IPPacket ipPacket,byte[] buffer, int startIndex, int packetLength) {
		super(ipPacket,buffer, startIndex, packetLength);
		seqNum = TCPIPUtils.toLong(buffer[startIndex + 4],buffer[startIndex + 5],buffer[startIndex + 6],buffer[startIndex + 7]);
		ackNum = TCPIPUtils.toLong(buffer[startIndex + 8],buffer[startIndex + 9],buffer[startIndex + 10],buffer[startIndex + 11]);
		headerLength = 20;
		setFlags(buffer[startIndex + 13]);
		window = TCPIPUtils.toIntUnsigned(buffer[startIndex + 14], buffer[startIndex + 15]);
		if(URG){
			urgPointer = TCPIPUtils.toIntUnsigned(buffer[startIndex + 18], buffer[startIndex + 19]);
		}
		data = new byte[packetLength - ipPacket.headerLength - headerLength];
		System.arraycopy(buffer, startIndex+headerLength, data, 0, data.length);
	}
	
	public TCPPacket(byte[] payload, int sourcePort, int destPort) {
		super(sourcePort,destPort);
		data = new byte[payload.length];
		System.arraycopy(payload, 0, data, 0, payload.length);
		headerLength = 20;
	}
	
	public void setFlags(int flags) {
		if((flags & (1 << 5)) > 0) URG = true;
		if((flags & (1 << 4)) > 0) ACK = true;
		if((flags & (1 << 3)) > 0) PSH = true;
		if((flags & (1 << 2)) > 0) RST = true;
		if((flags & (1 << 1)) > 0) SYN = true;
		if((flags & (1 << 0)) > 0) FIN = true;
	} 	

	public byte getFlags() {
		int flags = 0;
		
		if(URG) flags = flags | (1 << 5);
		if(ACK) flags = flags | (1 << 4);
		if(PSH) flags = flags | (1 << 3);
		if(RST) flags = flags | (1 << 2);
		if(SYN)	flags = flags | (1 << 1);
		if(FIN) flags = flags | (1 << 0);
		
		return (byte) flags;
	}


	@Override
	public byte[] toBytes() {
		byte[] ret = new byte[data.length];
		writeBytes(ret,0);
		return ret;
	}

	@Override
	public void writeBytes(byte[] buffer, int start) {
		//int packetLength = 3;
		System.arraycopy(TCPIPUtils.toTwoBytes(sourcePort), 0, buffer, 0, 2); // Source port
		System.arraycopy(TCPIPUtils.toTwoBytes(destPort), 0, buffer, 2, 2); // Destination port
		System.arraycopy(TCPIPUtils.toFourBytes(seqNum), 0, buffer, 4, 4); // Sequence number
		System.arraycopy(TCPIPUtils.toFourBytes(ackNum), 0, buffer, 8, 4); // Acknowledgement number (if ACK set)
		buffer[12] = (byte) ((headerLength << 4) & 0xF0); // Data offset + Reserved
		buffer[13] = getFlags(); //TCP flags
		System.arraycopy(TCPIPUtils.toTwoBytes(window), 0, buffer, 14, 2); // Window
		System.arraycopy(TCPIPUtils.toTwoBytes(0), 0, buffer, 16, 2); // 0's for checksum calculation
		if(URG){
			System.arraycopy(TCPIPUtils.toTwoBytes(urgPointer), 0, buffer, 18, 2); // Urgent pointer (if URG set)
		}
		else {
			System.arraycopy(TCPIPUtils.toTwoBytes(0), 0, buffer, 18, 2);
		}
		// No options
		System.arraycopy(TCPIPUtils.toTwoBytes(checksum(buffer)), 0, buffer, 16, 2); // UDP checksum
	}

	@Override
	public int getPacketLength() {
		return headerLength + data.length;
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
		System.arraycopy(data, 0, buffer, start, data.length);
	}
	
	/**
	 * Get Sequence and Acknowledgement number
	 * @return {SequenceNumber,AcknowledgementNumber}
	 */
	public long[] getTCPNumbers() {
		long[] numbers = {seqNum,ackNum};
		return numbers;
	}
	
	public void setSequenceNumber(long seqNum){
		this.seqNum = seqNum;
	}
	
	public void setAcknowledgementNumber(long ackNum){
		this.ackNum = ackNum;
	}

}
