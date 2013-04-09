package hu.edudroid.sniffer;

import java.nio.ByteBuffer;

public class TCPIPUtils {
	
	public static int getPacketLength(ByteBuffer packet, int packetStart,
			int bufferEnd) {
		// Not enough bytes
		if (bufferEnd - packetStart < 4) {
			return -1;
		} else {
			return toIntUnsigned(packet.get(packetStart + 2), packet.get(packetStart + 3));
		}
	}
	
	

	public static int toIntUnsigned(byte hb, byte lb) {
		return ((hb < 0?((int)hb) + 128:((int)hb)) << 8) + (lb < 0?((int)lb) + 128:((int)lb));
	}
	public static String ipAddressToString(byte[] data, int offset) {
		String ret = "" + ((data[offset] < 0?((int)data[offset]) + 128:((int)data[offset])));
		ret = ret + "." + ((data[offset + 1] < 0?((int)data[offset + 1]) + 128:((int)data[offset + 1])));
		ret = ret + "." + ((data[offset + 2] < 0?((int)data[offset + 2]) + 128:((int)data[offset + 2])));
		ret = ret + "." + ((data[offset + 3] < 0?((int)data[offset + 3]) + 128:((int)data[offset + 3])));
		
		return ret;
	}
}
