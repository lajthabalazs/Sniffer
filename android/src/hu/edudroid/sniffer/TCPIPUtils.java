package hu.edudroid.sniffer;

import java.nio.ByteBuffer;

public class TCPIPUtils {

	public static int getPacketLength(ByteBuffer packet, int packetStart,
			int bufferEnd) {
		// Not enough bytes
		if (bufferEnd - packetStart < 4) {
			return -1;
		} else {
			return toInt(packet.get(packetStart + 2), packet.get(packetStart + 3));
		}
	}
	
	

	public static int toInt(byte hb, byte lb) {
		return ((int) hb) << 8 + lb;
	}
}
