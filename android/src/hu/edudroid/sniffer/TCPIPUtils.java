package hu.edudroid.sniffer;

public class TCPIPUtils {	

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
