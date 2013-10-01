package test_pakety;

import gui.Gui;

import java.awt.EventQueue;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
 
public class PacketCapturer {
 
	public static ArrayList<String> devArray;
	
	public static String byteToHex(byte b) {
	    int i = b & 0xFF;
	    return Integer.toHexString(i);
	  }
	
	public static String bytesToHexString(byte[] bytes) { 
		StringBuilder sb = new StringBuilder(); 
		
		for(byte b : bytes) { 
			sb.append(String.format("%02x", b&0xff)); 
			} 
		
		return sb.toString(); 
	} 

    
	@SuppressWarnings({ "resource", "unchecked", "rawtypes" })
	public static void main(String[] args) {
		
		int i = 0;
		
        try {
        	
        	//Gui app = new Gui();
        	//app.gui();
        	//devArray = new ArrayList<String>();

        	// zoznamy so zariadeniami na pc
        	List alldevs = new ArrayList();
        	List<PcapIf> alldevs_tmp = new ArrayList<PcapIf>();
        	
            StringBuilder errbuf = new StringBuilder();
            String err = "";

            //nacitanie sietovych zariadeni
            int r = Pcap.findAllDevs(alldevs, errbuf);
            
            if (r != Pcap.OK) {
                System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
                //Gui.vypis(String.format("Can't read list of devices, error is %s\n", errbuf.toString()));
                return;
            }
            
            for (Object dev: alldevs) {
            	alldevs_tmp.add((PcapIf)dev);
            	//devArray.add(dev.toString());
            }

            System.out.println(alldevs_tmp.size() + " network devices found:");
            //Gui.vypis(String.format(alldevs_tmp.size() + " network devices found:\n"));
            
            i = 0;
            
            for (PcapIf device: alldevs_tmp) {
                String description = (device.getDescription() != null) ? device.getDescription(): "No description available";
                System.out.printf("#%d: %s [%s]\n", ++i, device.getName(), description);
                
                //Gui.vypis(String.format("#%d: %s [%s]\n", i, device.toString(), description));
            }
            
            System.out.println("Vyberte 1. zariadenie");
            int number = new Scanner(System.in).nextInt();
            PcapIf device =  alldevs_tmp.get(number - 1);
            
            System.out.println("Vyberte 2. zariadenie");
            number = new Scanner(System.in).nextInt();
            PcapIf device2 = alldevs_tmp.get(number - 1);
 
            int snaplen = 64 * 1024;           // cely packet
            int flags = Pcap.MODE_PROMISCUOUS; // vsetko co pride na sietovu kartu
            int timeout = 1 * 1000;           // 10ms
 
            //Open the selected device to capture packets
            Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
            Pcap pcap2 = Pcap.openLive(device2.getName(), snaplen, flags, timeout, errbuf);
            
            if (pcap == null || pcap2 == null) {
                System.err.printf("Error while opening device for capture: " + errbuf.toString());
                return;
            }
            
            System.out.println("Zariadenia otvorene");
 
            //set filter
            System.out.println("Zadajte filter: ");
            
            PcapBpfProgram program = new PcapBpfProgram();
            //String filter = "ip proto \\icmp";
            String filter = new Scanner(System.in).nextLine();
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
         
            System.out.println("Zacinam tahat packety ...");
            
           
    		
    		PcapPacketHandler<String> jpacketHandler2 = new PcapPacketHandler<String>() {

            	int n_arp, n_tcp, n_udp, n_icmp;
				int n_raw, n_snap, n_llc, n_ipx, n_sap;
				int unkw;
				int actual;
				int port;
            	
    			public void nextPacket(PcapPacket packet, String user) {

    				JBuffer buffer = packet;
    				
    				byte headb[] = buffer.getByteArray(0, buffer.size());
    				String head = bytesToHexString(headb);
    				
    				actual = buffer.getUShort(12);
    				
    				if (actual >= 1536) {
    					//je to ethernet 2 atd...
    					if (actual == 2054)
    						n_arp++;
    					else if (actual == 2048) {

    						switch (buffer.getUByte(23)) {
    							case 1: n_icmp++; break;
    							case 6: n_tcp++; break;
    							case 17: n_udp++; break;
    							default: unkw++; break;
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
    							default: unkw++; break;
    						}
    					}
    				}
    				
    				System.out.printf("%s, ethertype: %d, port: %d, caplen: %d, len: %d\narp: %d, tcp: %d, udp: %d, icmp: %d, raw: %d, snap: %d, llc: %d, ipx: %d, sap: %d, unkw: %d, user: %s\n", 
    						new Date(packet.getCaptureHeader().timestampInMillis()),
    						buffer.getUShort(12),
    						port,
    						packet.getCaptureHeader().caplen(), 
    						packet.getCaptureHeader().wirelen(),
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
            
    		EventQueue.invokeLater(new Runnable() {
				
				@Override
				public void run() {
					// TODO Auto-generated method stub
					
		            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

		            	int n_arp, n_tcp, n_udp, n_icmp;
						int n_raw, n_snap, n_llc, n_ipx, n_sap;
						int unkw;
						int actual;
						int port;
		            	
		    			public void nextPacket(PcapPacket packet, String user) {

		    				JBuffer buffer = packet;
		    				Ip4 ip = new Ip4();
		    				
		    				byte headb[] = buffer.getByteArray(0, buffer.size());
		    				String head = bytesToHexString(headb);
		    				
		    				actual = buffer.getUShort(12);
		    				
		    				if (actual >= 1536) {
		    					//je to ethernet 2 atd...
		    					if (actual == 2054)
		    						n_arp++;
		    					else if (actual == 2048) {

		    						switch (buffer.getUByte(23)) {
		    							case 1: n_icmp++; break;
		    							case 6: n_tcp++; break;
		    							case 17: n_udp++; break;
		    							default: unkw++; break;
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
		    							default: unkw++; break;
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
					
					pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "pcap");
				}
			});
    		
    		
            
            pcap2.loop(Pcap.LOOP_INFINITE, jpacketHandler2, "pcap2");
            
            pcap.close();
            pcap2.close();
            
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}