package hu.edudroid.sniffer.test;

import java.nio.ByteBuffer;

import hu.edudroid.tcp_utils.TCPIPUtils;
import hu.edudroid.sniffer.IPPacket;
import hu.edudroid.sniffer.MainActivity;
import hu.edudroid.sniffer.TCPPacket;
import hu.edudroid.sniffer.UDPPacket;
import android.test.ActivityInstrumentationTestCase2;

public class ChecksumTest extends
		ActivityInstrumentationTestCase2<MainActivity> {

	@SuppressWarnings("deprecation")
	public ChecksumTest() {
		super("hu.edudroid.sniffer", MainActivity.class);
	}

	protected void setUp() throws Exception {
		//MainActivity mainActivity = getActivity();  
		super.setUp();
	}
		
	public void testLocalHostHeader() {
		//UDP packet from 127.0.0.1:1900 to 127.0.0.1:1900 header checksum test
		ByteBuffer buffer = ByteBuffer.allocate(34);
		buffer.put(new byte[]{0x45, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00 , 0x01, 0x7f, 0x00, 0x00, 0x01, 0x07, 0x6c, 0x07, 0x6c, 0x00, 0x06, 0x00, 0x00, 0x01, 0x10, 0x01, 0x10, 0x01, 0x10}); 
		IPPacket packet = new IPPacket(buffer, 0, 34);
		
	
		byte[] header = new byte[20];
		System.arraycopy(packet.toBytes(), 0, header, 0, 20);
		
		
		System.arraycopy(TCPIPUtils.toTwoBytes(0), 0, header, 10, 2); // 0's for checksum calculation
		int actual = TCPIPUtils.checksum(header);
		int expected = (~0x8336) & 0x0000FFFF;  //4500 + 0022 + 0000 + 4011 + 0000 + 7f00 + 0001 + 7f00 + 0001 = 18335 ==> 8335 + 1 = 8336
		assertEquals(expected, actual); 
	}
	
	public void testLocalHostUDPChecksum() {
		//UDP packet from 127.0.0.1:1900 to 127.0.0.1:1900 udp checksum test
		ByteBuffer buffer = ByteBuffer.allocate(34);
		buffer.put(new byte[]{0x45, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00 , 0x01, 0x7f, 0x00, 0x00, 0x01, 0x07, 0x6c, 0x07, 0x6c, 0x00, 0x06, 0x00, 0x00, 0x01, 0x10, 0x10, 0x01, 0x01, 0x10});
		IPPacket packet = new IPPacket(buffer, 0, 34);
		
		byte[] data = packet.toBytes();
		System.arraycopy(TCPIPUtils.toTwoBytes(0), 0, data, packet.headerLength+6, 2); // 0's for checksum calculation
		int actual = packet.payload.checksum(data);
		int expected = (~0x1f3d) & 0x0000FFFF;
		assertEquals(expected, actual); 
	}
	
	public void testHeaderCheckSumRecalculate() {
		//Calculate checksum again, if it gives zero it means it's working
		ByteBuffer buffer = ByteBuffer.allocate(34);
		buffer.put(new byte[]{0x45, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00 , 0x01, 0x7f, 0x00, 0x00, 0x01, 0x07, 0x6c, 0x07, 0x6c, 0x00, 0x06, 0x00, 0x00, 0x01, 0x10, 0x10, 0x01, 0x01, 0x10}); //UDP packet from 127.0.0.1:1900 to 127.0.0.1:1900
		IPPacket packet = new IPPacket(buffer, 0, 34);
		
		byte[] header = new byte[20];
		System.arraycopy(packet.toBytes(), 0, header, 0, 20);
		
		int actual = TCPIPUtils.checksum(header);
		int expected = 0;
		assertEquals(expected, actual); 
	}
	
	public void testUDPCheckSumRecalculate() {
		//Calculate checksum again, if it gives zero it means it's working
		ByteBuffer buffer = ByteBuffer.allocate(34);
		buffer.put(new byte[]{0x45, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00 , 0x01, 0x7f, 0x00, 0x00, 0x01, 0x07, 0x6c, 0x07, 0x6c, 0x00, 0x06, 0x00, 0x00, 0x01, 0x10, 0x10, 0x01, 0x01, 0x10}); //UDP packet from 127.0.0.1:1900 to 127.0.0.1:1900
		IPPacket packet = new IPPacket(buffer, 0, 34);
		
		byte[] data = packet.toBytes();
		int actual = packet.payload.checksum(data);
		int expected = 0;
		assertEquals(expected, actual); 
	}
}


