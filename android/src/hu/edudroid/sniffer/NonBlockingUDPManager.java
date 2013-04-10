package hu.edudroid.sniffer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import android.util.SparseArray;

public class NonBlockingUDPManager {	
	
	private static final int MAX_BUFFER_SIZE = 2048;
	private MyVpnService service;
	private HashMap<Byte, HashMap<Byte, HashMap<Byte, HashMap<Byte, SparseArray<SparseArray<DatagramChannel>>>>>> channels = new HashMap<Byte, HashMap<Byte,HashMap<Byte,HashMap<Byte,SparseArray<SparseArray<DatagramChannel>>>>>>();
	private HashMap<Byte, HashMap<Byte, HashMap<Byte, SparseArray<SparseArray<DatagramChannel>>>>> channels1; 
	private HashMap<Byte, HashMap<Byte, SparseArray<SparseArray<DatagramChannel>>>> channels2;	
	private HashMap<Byte, SparseArray<SparseArray<DatagramChannel>>> channels3;	
	private SparseArray<SparseArray<DatagramChannel>> channels4;
	private SparseArray<DatagramChannel> channels5;
	private DatagramChannel channel;
	private HashMap<DatagramChannel, ByteBuffer> outputBuffers = new HashMap<DatagramChannel, ByteBuffer>();
	private HashMap<DatagramChannel, ByteBuffer> inputBuffers = new HashMap<DatagramChannel, ByteBuffer>();
	private List<DatagramChannel> channelList = new ArrayList<DatagramChannel>();
	private ByteBuffer buffer;

	public NonBlockingUDPManager(MyVpnService service){
		this.service = service;
	}
	
	protected void queMessage(Packet packet) {
		channels1 = channels.get(packet.destIp[0]);
		if (channels1 == null) {
			channels1 = new HashMap<Byte, HashMap<Byte,HashMap<Byte,SparseArray<SparseArray<DatagramChannel>>>>>();
			channels.put(packet.destIp[0], channels1);
		}

		channels2 = channels1.get(packet.destIp[1]);
		if (channels2 == null) {
			channels2 = new HashMap<Byte,HashMap<Byte,SparseArray<SparseArray<DatagramChannel>>>>();
			channels1.put(packet.destIp[1], channels2);
		}

		channels3 = channels2.get(packet.destIp[2]);
		if (channels3 == null) {
			channels3 = new HashMap<Byte,SparseArray<SparseArray<DatagramChannel>>>();
			channels2.put(packet.destIp[2], channels3);
		}

		channels4 = channels3.get(packet.destIp[3]);
		if (channels4 == null) {
			channels4 = new SparseArray<SparseArray<DatagramChannel>>();
			channels3.put(packet.destIp[3], channels4);
		}

		channels5 = channels4.get(packet.destPort);
		if (channels5 == null) {
			channels5 = new SparseArray<DatagramChannel>();
			channels4.put(packet.destPort, channels5);
		}

		channel = channels5.get(packet.sourcePort);
		if (channel == null) {
			try {
				channel = DatagramChannel.open();			
				channel.socket().bind(new InetSocketAddress(packet.sourcePort));
				channel.connect(new InetSocketAddress(InetAddress.getByAddress(packet.destIp), packet.destPort));
				channels5.put(packet.sourcePort, channel);
				buffer = ByteBuffer.allocate(MAX_BUFFER_SIZE);
				buffer.put(packet.data, packet.dataOffset, packet.dataLength);
				outputBuffers.put(channel, buffer);
			} catch (UnknownHostException e) {
				e.printStackTrace();
				return;
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}
		}
		buffer = outputBuffers.get(channel);
		// Queues message in the proper output buffer
		if ((buffer != null) && (buffer.remaining() > packet.dataLength)) {
			buffer.put(packet.data, packet.dataOffset, packet.dataLength);
		}
	}
	
	public void flushQueus(){
		for (DatagramChannel channel : channelList) {
			if (outputBuffers.get(channel).position() > 0) {
				try {
					
					int written = channel.write(outputBuffers.get(channel));
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}
}
