package switch_workClasses;

import java.util.Date;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.Pcap.Direction;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;

import switch_gui.Gui;
import switch_main.SwitchMain;

public class PacketHandler implements Runnable {
	
	StringBuilder errbuf = new StringBuilder();
	int snaplen = 64 * 1024;           	// cely packet
    int flags = Pcap.MODE_PROMISCUOUS; 	// vsetko co pride na sietovu kartu
    int timeout = 1 * 1000;           	// 10ms
	
	public void getPacket (PcapIf device, String filter, String user) {
		
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }
        
        System.out.println(device.getDescription() + " otvorene.");

        //nastavenie filtru
        PcapBpfProgram program = new PcapBpfProgram();
        int opt = 0;
        int mask = 0xffffff00;

        if (pcap.compile(program, filter, opt, mask) != Pcap.OK) {
        	System.out.println(pcap.getErr());
        	return;
        }
        
        if (pcap.setFilter(program) != Pcap.OK) {
        	System.out.println(pcap.getErr());
        	return;
        }
        
        pcap.setDirection(Direction.OUT);
        
        System.out.println("Zacinam tahat packety ...");
		
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

        	int n_arp, n_tcp, n_udp, n_icmp;
			int n_raw, n_snap, n_llc, n_ipx, n_sap;
			int unkw;
			int actual;
			int port;
	            	
			public void nextPacket(PcapPacket packet, String user) {

				JBuffer buffer = packet;
				Ip4 ip = new Ip4();
				
				actual = buffer.getUShort(12);
				
				if (actual >= 1536) {
					//je to ethernet 2 atd...
					if (actual == 2054)
						n_arp++;
					else if (actual == 2048) {
    						switch (buffer.getUByte(23)) {
							case 1: n_icmp++; Gui.incCount_icmp(); break;
							case 6: n_tcp++; Gui.incCount_tcp(); break; 
							case 17: n_udp++; Gui.incCount_udp(); break;
							default: unkw++; Gui.incCount_unkw(); break;
						}
					}
				}
				else if (actual > 0 && actual <= 1500) {
					//je to ieee atd...
					if (buffer.getUByte(14) == 3)
						n_llc++;
					else {
						switch(buffer.getUShort(14)) {
							case 43690: n_snap++; break;
							case 57568: n_ipx++; break;
							case 61680: n_sap++; break;
							case 65535: n_raw++; break;
							default: unkw++; Gui.incCount_unkw(); break;
						}
					}
				}
				
				if (packet.hasHeader(ip)) {
					String src = new String();
					//String dst = new String();
					int port;
					
					src = asString(buffer.getByteArray(6, 6));
					//dst = asString(buffer.getByteArray(0, 6));
					port = Integer.parseInt(user);
					
					//Gui.vypis(String.format("DST: %s SRC: %s port: %d\n", dst, src, port));
					
					if (!SwitchMain.obshaujeMac(src, port)) {
						SwitchMain.pridajZaznam(src, port);
						Gui.pridajRiadok(src, port);
					}
					
				}
	    				
				System.out.printf("%s, ethertype: %d, port: %d, caplen: %d, len: %d, dip: %s, sip: %s\narp: %d, tcp: %d, udp: %d, icmp: %d, raw: %d, snap: %d, llc: %d, ipx: %d, sap: %d, unkw: %d, user: %s\n", 
						new Date(packet.getCaptureHeader().timestampInMillis()),
						buffer.getUShort(12),
						port,
						packet.getCaptureHeader().caplen(), 
						packet.getCaptureHeader().wirelen(),
						org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()),
						org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()),
						n_arp,
						n_tcp,
						n_udp, 
						n_icmp,
						n_raw, 
						n_snap, 
						n_llc, 
						n_ipx, 
						n_sap,
						unkw,
						user
				);
				
			}
        };
        
        while (true) {
        	if (!Gui.start)
        		pcap.loop(1, jpacketHandler, user);
        	else {
        		if (user.equals("0"))
                	SwitchMain.dev_0_aktivny = false;
        		if (user.equals("1"))
                	SwitchMain.dev_1_aktivny = false;
        	}
        }
        
        /*
		if (user.equals("0"))
        	SwitchMain.dev_0_aktivny = false;
		if (user.equals("1"))
        	SwitchMain.dev_1_aktivny = false;
		pcap.close();
        */
	}
	
	private static String asString(final byte[] mac) {  
		
		final StringBuilder buf = new StringBuilder();  
		
		for (byte b : mac) {  
			if (buf.length() != 0) {  
				buf.append(':');  
			}  
			
			if (b >= 0 && b < 16) {  
				buf.append('0');  
			}  
			
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());  
	    }
		
		return buf.toString();  
	}

	@Override
	public void run() {
		// TODO Auto-generated method stub
		
	}

}
