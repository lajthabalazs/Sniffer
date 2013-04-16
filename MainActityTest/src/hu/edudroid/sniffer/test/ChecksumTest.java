package hu.edudroid.sniffer.test;

import java.nio.ByteBuffer;

import hu.edudroid.tcp_utils.TCPIPUtils;
import hu.edudroid.sniffer.MainActivity;
import hu.edudroid.sniffer.Packet;
import android.test.ActivityInstrumentationTestCase2;

public class ChecksumTest extends
		ActivityInstrumentationTestCase2<MainActivity> {

	public ChecksumTest() {
		super("hu.edudroid.sniffer", MainActivity.class);
	}

	protected void setUp() throws Exception {
		MainActivity mainActivity = getActivity();  
		super.setUp();
	}
	
	public byte[] getHeader(Packet packet){
		byte[] header = new byte[20];
		header[0] = 69;// TCPIPUtils.toByte(version, ihl);
		header[1] = 0; // DSCP, ECN
		System.arraycopy(TCPIPUtils.toTwoBytes(packet.packetLength), 0, header, 2, 2); // Total length
		System.arraycopy(TCPIPUtils.toTwoBytes(0), 0, header, 4, 2); // Identification
		header[6] = 0; // Flags, Fragment offset part 1
		header[7] = 0; // Flags, Fragment offset part 2
		header[8] = 64; // TTL
		header[9] = packet.protocol;
		System.arraycopy(TCPIPUtils.toTwoBytes(0), 0, header, 4, 2); // 0's for Header checksum calculation
		System.arraycopy(packet.sourceIp, 0, header, 12, 4);
		System.arraycopy(packet.destIp, 0, header, 16, 4);
		return header;
	}
	
	public void testEmptyHeader() {
		ByteBuffer buffer = ByteBuffer.allocate(20);
		buffer.put(new byte[20]);
		Packet packet = new Packet(buffer, 0, 20);
		
		int actual = packet.IPChecksum(getHeader(packet));
		int expected = (~0x8500) & 0x0000FFFF;  //version,ihl + ttl ==> 0x4500 + 0x4000 = 0x8500
		assertEquals(expected, actual); 
	}
	
	public void testLocalHostHeader() {
		ByteBuffer buffer = ByteBuffer.allocate(34);
		buffer.put(new byte[]{0x45, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00 , 0x01, 0x7f, 0x00, 0x00, 0x01, 0x6c, 0x07, 0x6c, 0x07, 0x00, 0x06, 0x00, 0x00, 0x01, 0x10, 0x01, 0x10, 0x01, 0x10}); //UDP packet from 127.0.0.1:1900 to 127.0.0.1:1900
		Packet packet = new Packet(buffer, 0, 34);
		
	
		int actual = packet.IPChecksum(getHeader(packet));
		int expected = (~0x8336) & 0x0000FFFF;  //4500 + 0022 + 0000 + 4011 + 0000 + 7f00 + 0001 + 7f00 + 0001 = 18335 ==> 8335 + 1 = 8336
		assertEquals(expected, actual); 
	}
	
	public void testLocalHostUDPChecksum() {
		ByteBuffer buffer = ByteBuffer.allocate(34);
		buffer.put(new byte[]{0x45, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00 , 0x01, 0x7f, 0x00, 0x00, 0x01, 0x07, 0x6c, 0x07, 0x6c, 0x00, 0x06, 0x00, 0x00, 0x01, 0x10, 0x10, 0x01, 0x01, 0x10}); //UDP packet from 127.0.0.1:1900 to 127.0.0.1:1900
		Packet packet = new Packet(buffer, 0, 34);
		
		byte[] data = packet.toByteArray();
		data[26] = 0; //zeroing UDP checksum to calculate it again
		data[27] = 0;
		int actual = packet.UDPChecksum(data);
		int expected = (~0x1f3d) & 0x0000FFFF;
		assertEquals(expected, actual); 
	}

}


