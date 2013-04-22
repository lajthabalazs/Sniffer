package hu.edudroid.tcp_utils;

public class TCPIPUtils {	

	public static void main(String[] args) {
		for (int i = 0; i < 256; i++) {
			System.out.println(i);
			for (int j = 0; j < 256; j++) {
				byte[] bytes = toTwoBytes(i * 256 + j);
				if (toIntUnsigned(bytes[0], bytes[1]) != i * 256 + j) {
					System.out.println("Not equal " + (i * 256 + j) + " " + bytes[0] + "," + bytes[1]);
				}
				
			}
		}
	}
	
	public static int toIntUnsigned(byte hb, byte lb) {
		return ((hb < 0?256 + (int)hb:((int)hb)) << 8) + (lb < 0?256 + (int)lb:((int)lb));
	}

	public static byte toByte(int first, int second) {
		return (byte)((first << 4) + second);
	}
	
	public static long toLong(byte hhb, byte hlb, byte lhb, byte llb) {
		long number = 0L;
		number = number & (hhb << 24);
		number = number & (hlb << 16);
		number = number & (lhb << 8);
		number = number & llb;
		return number;
	}
	public static byte[] toTwoBytes(int value) {
		byte[] ret = new byte[2];
		ret[1] = (byte)(value & 0xFF);
		ret[0] = (byte)((value >> 8) & 0xFF);
		return ret;
	}

	public static byte[] toFourBytes(long value) {
		byte[] ret = new byte[4];
		ret[3] = (byte)(value & 0xFF);
		ret[2] = (byte)((value >> 8) & 0xFF);
		ret[1] = (byte)((value >> 16) & 0xFF);
		ret[0] = (byte)((value >> 24) & 0xFF);
		return ret;
	}

	public static String ipAddressToString(byte[] data, int offset) {
		String ret = "" + ((data[offset] < 0?(256 +(int)data[offset]):((int)data[offset])));
		ret = ret + "." + ((data[offset + 1] < 0?(256 + (int)data[offset + 1]):((int)data[offset + 1])));
		ret = ret + "." + ((data[offset + 2] < 0?(256 + (int)data[offset + 2]):((int)data[offset + 2])));
		ret = ret + "." + ((data[offset + 3] < 0?(256 + (int)data[offset + 3]):((int)data[offset + 3])));
		return ret;
	}
	
	public static long getLongFromAddress(byte[] address, int port) {
		if (port < 0 || port > 0xFFFF || address.length != 4) {
			return -1;
		} else {
			long ret = (address[0] & 0xFF);
			ret = ret << 8;
			ret = ret | (address[1] & 0xFF);
			ret = ret << 8;
			ret = ret | (address[2] & 0xFF);
			ret = ret << 8;
			ret = ret | (address[3] & 0xFF);
			ret = ret << 16;
			ret = ret | port;
			return ret;
		}
	}
}
