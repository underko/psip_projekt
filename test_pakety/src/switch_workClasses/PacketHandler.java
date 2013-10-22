package switch_workClasses;

import java.util.Date;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.Pcap.Direction;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;

import switch_gui.Gui;
import switch_main.SwitchMain;

public class PacketHandler implements Runnable {
	
	StringBuilder errbuf = new StringBuilder();
	int snaplen = 64 * 1024;           	// cely packet
    int flags = Pcap.MODE_NON_BLOCKING; 	// vsetko co pride na sietovu kartu
    int timeout = 1 * 1000;           	// 10ms
	
	@SuppressWarnings("deprecation")
	public void getPacket (PcapIf device, String filter, String user) {
		
        final Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }
        
        System.out.println(device.getDescription() + " otvorene.");										//debug

        //nastavenie filtru
        PcapBpfProgram program = new PcapBpfProgram();
        int opt = 0;
        int mask = 0xffffff00;

        if (pcap.compile(program, filter, opt, mask) != Pcap.OK) {
        	System.out.println(pcap.getErr());
        	return;
        }
        
        System.out.println("som tu");
        
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
				Ethernet eth = new Ethernet();
				Ip4 ip = new Ip4();
				System.out.println("tu som skus ma");			////
				if (packet.hasHeader(Ethernet.ID)) {
					eth = packet.getHeader(eth);
					System.out.println("tu som eth");			////
					String srcMac = asString(buffer.getByteArray(6, 6));
					String dstMac = asString(buffer.getByteArray(0, 6));			//pouzijeme na posielanie
					
					port = Integer.parseInt(user);
					
					if (!SwitchMain.obshaujeMac(srcMac, port)) {
						SwitchMain.pridajZaznam(srcMac, port);
						Gui.pridajRiadok(srcMac, port);
					}
					
					//pridanie do radu na prislusny port
					int port_tmp = SwitchMain.obsahujeMac(dstMac);
					
					switch (port_tmp) {
						case 0:
							SwitchMain.quePort_0.add(packet);
							break;
						case 1:
							SwitchMain.quePort_1.add(packet);
							break;
						default:
							SwitchMain.quePort_0.add(packet);
							SwitchMain.quePort_1.add(packet);	
							break;
					}
					
					//vyposielanie vsetkeho co mam
					if (user != null && user == "0") {
						System.out.println("port 0 idem posielat");
						while (!SwitchMain.quePort_0.isEmpty()) {
							System.out.println("port 0 posielam");
							pcap.sendPacket(SwitchMain.quePort_0.get(0));
							System.out.println("posielam 0: " + SwitchMain.quePort_0.get(0));
							SwitchMain.quePort_0.remove(0);
						}
					}
					else if (user != null && user == "1") {
						System.out.println("port 1 idem posielat");
						while (!SwitchMain.quePort_1.isEmpty()) {
							System.out.println("port 1 posielam");
							pcap.sendPacket(SwitchMain.quePort_1.get(0));
							System.out.println("posielam 1: " + SwitchMain.quePort_0.get(0));
							SwitchMain.quePort_1.remove(0);
						}
					}
				}
				
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
        	System.out.println("tu som mozem zacat?" + user);				////
        	if (Gui.mozeZacat == false /*mozeZacat po stlaceni start sa zmeni na false*/) {
        		System.out.println("mozezacat == false" + user);			////
        		if (user.equals("0")) {
        			System.out.println("nastavujem 0 na true");
                	SwitchMain.dev_0_aktivny = true;
        		}
        		if (user.equals("1")) {
        			System.out.println("nastavujem 1 na true");
                	SwitchMain.dev_1_aktivny = true;
        		}
        		
        		//pcap.loop(1, jpacketHandler, user);
        		
        		pcap.dispatch(1, jpacketHandler, user);
        			
        	}
        	else {
        		System.out.println("mozezacat == true"  + user);			////
        		if (user.equals("0"))
                	SwitchMain.dev_0_aktivny = false;
        		if (user.equals("1"))
                	SwitchMain.dev_1_aktivny = false;
        		
        		break;
        	}
        }
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
