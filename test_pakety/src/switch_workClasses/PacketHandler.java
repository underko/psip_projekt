package switch_workClasses;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.Pcap.Direction;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
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
        
        pcap.setDirection(Direction.IN);
        
        System.out.println("Zacinam tahat packety ...");
		
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

        	int n_arp, n_tcp, n_udp, n_icmp;
			int n_raw, n_snap, n_llc, n_ipx, n_sap;
			int unkw;
			
			int actual;
			int port, index;
	            	
			public void nextPacket(PcapPacket packet, String user) {

				JBuffer buffer = new JBuffer(packet);
				Ethernet eth = new Ethernet();
				
				System.out.println(user + ": zaciatok packethandlera");
				
				if (packet.hasHeader(Ethernet.ID)) {								//len ethernetove ramce beriem
					eth = packet.getHeader(eth);									//vytiahnem si hlavicku
					String srcMac = asString(buffer.getByteArray(6, 6));			//src na generovanie tabulky
					String dstMac = asString(buffer.getByteArray(0, 6));			//pouzijeme na posielanie podla tabulky
					port = Integer.parseInt(user);
					
					if (!SwitchMain.obsahujePrijatePort_0_1(packet, port)) {				//zistujem ci som taky posielal
					
						SwitchMain.pridajDoPrijatePort_0_1(packet, port);
						Gui.vypis(String.format("prijate p0: %d, prijate p1: %d\n", SwitchMain.prijatePort_0.size(), SwitchMain.prijatePort_1.size()));
						
						index = SwitchMain.getCisloRiadku(srcMac);					//ci sa nachadza v tabulke
						System.out.println(String.format("index: %d, dst: %s, src: %s size: %d", index, dstMac, srcMac, SwitchMain.macTabList.size()));
						
						if (index != -1)
							SwitchMain.odstranZaznam(index);
						
						SwitchMain.pridajZaznam(srcMac, port);
						Gui.obnovRiadky();
						
						//pridanie do radu na prislusny port
						int port_tmp = SwitchMain.obsahujeMac(dstMac);
						
						System.out.println("prisiel packet z " + user + " a ide na port " + port_tmp);
						
						switch (port_tmp) {
							case 0:
								if (user == "0") break;										//prislo z rovnokaho portu kam by malo ist takze discard
								SwitchMain.quePort_0.add(packet);
								break;
							case 1:
								if (user == "1") break;										//prislo z rovnokaho portu kam by malo ist takze discard
								SwitchMain.quePort_1.add(packet);
								break;
							default:
								if (user == "1") {
									Gui.vypis("user 1 dava packet na port 0\n");
									SwitchMain.quePort_0.add(packet);
									break;
								}
								else if (user == "0") {
									Gui.vypis("user 0 dava packet na port 1\n");
									SwitchMain.quePort_1.add(packet);
									break;	
								}								
								break;
						}
						
						//vyposielanie vsetkeho co mam
						if (user != null && user == "0") {
							System.out.printf("port 0 idem posielat %d\n", SwitchMain.quePort_0.size());
							while (!SwitchMain.quePort_0.isEmpty()) {
								pcap.sendPacket(SwitchMain.quePort_0.get(0));
								System.out.println("posielam na port 0");
								SwitchMain.quePort_0.remove(0);
							}
						}
						else if (user != null && user == "1") {
							System.out.printf("port 1 idem posielat %d\n", SwitchMain.quePort_1.size());
							while (!SwitchMain.quePort_1.isEmpty()) {
								pcap.sendPacket(SwitchMain.quePort_1.get(0));
								System.out.println("posielam na port 1");
								SwitchMain.quePort_1.remove(0);
							}
						}

						//statistika a dalsie blbiny
						actual = buffer.getUShort(12);
						
						if (actual >= 1536) {
							//je to ethernet 2 atd...
							if (actual == 2054) {
								n_arp++;
								Gui.incCount_arp();
							}
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
								n_llc++;				//llc
							else {
								switch(buffer.getUShort(14)) {
									case 43690: n_snap++; break; 	//snap
									case 57568: n_ipx++; break;		//ipx
									case 61680: n_sap++; break;		//sap
									case 65535: n_raw++; break;		//raw
									default: unkw++; Gui.incCount_unkw(); break; //unkw
								}
							}
						}
				
				
					}
					else {
						Gui.vypis(user + ": wtf !? taky tu uz bol !\n");
						SwitchMain.odstranZPrijatePort_0_1(packet, port);
					}
				}
			}
        };
        
        while (true) {
        	if (Gui.mozeZacat == false /*mozeZacat po stlaceni start sa zmeni na false*/) {
        		System.out.println("posielame  " + user);
        		if (user.equals("0")) {
                	SwitchMain.dev_0_aktivny = true;
        		}
        		if (user.equals("1")) {
                	SwitchMain.dev_1_aktivny = true;
        		}
        		
        		pcap.dispatch(1, jpacketHandler, user);
        		System.out.println("loop " + user);	
        	}
        	else {
        		if (user.equals("0"))
                	SwitchMain.dev_0_aktivny = false;
        		if (user.equals("1"))
                	SwitchMain.dev_1_aktivny = false;
        		
        		break;
        	}
        }
        
        pcap.close();
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
