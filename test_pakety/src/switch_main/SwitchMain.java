package switch_main;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;

import switch_gui.Gui;
import switch_workClasses.PacketHandler;
import switch_workClasses.Posielanie;
import switch_workClasses.PoslanyPacket;
import switch_workClasses.RiadokTabulka;
 
public class SwitchMain {
 
	public static ArrayList<RiadokTabulka> macTabList = new ArrayList<RiadokTabulka>();
	public static PcapIf device_0 = new PcapIf();
	public static PcapIf device_1 = new PcapIf();
	
	public static List<PcapIf> alldevs_tmp;
	
	public static boolean dev_0_aktivny;
	public static boolean dev_1_aktivny;
	
	public static ArrayList<PcapPacket> quePort_0 = new ArrayList<PcapPacket>();
	public static ArrayList<PcapPacket> quePort_1 = new ArrayList<PcapPacket>();
	
	public static ArrayList<PoslanyPacket> prijatePort_0 = new ArrayList<PoslanyPacket>();
	public static ArrayList<PoslanyPacket> prijatePort_1 = new ArrayList<PoslanyPacket>();
	
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

    
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static void main(String[] args) {
		
		int i = 0;
		
        try {
        	
        	Gui app = new Gui();
        	app.gui();

        	// zoznamy so zariadeniami na pc
        	List alldevs = new ArrayList();
        	alldevs_tmp = new ArrayList<PcapIf>();
        	
            StringBuilder errbuf = new StringBuilder();

            //nacitanie sietovych zariadeni
            Gui.vypis(String.format("Vyhladavam NICs ..."));
            int r = Pcap.findAllDevs(alldevs, errbuf);
            
            if (r != Pcap.OK) {
                Gui.vypis(String.format("Can't read list of devices, error is %s\n", errbuf.toString()));
                return;
            }
            
            for (Object dev: alldevs) {
            	alldevs_tmp.add((PcapIf)dev);
            }

            Gui.vypis(String.format(" " + alldevs_tmp.size() + " najdene zariadenia pridane do cmb vyberu.\n"));
            
            i = 0;
            
            int hashtag = 0;
            
            for (PcapIf device: alldevs_tmp) {
                String description = (device.getDescription() != null) ? device.getDescription(): "No description available";
                System.out.printf("#%d: %s [%s]\n", ++i, device, description);
                Gui.cmbDevArr.add(new String(hashtag++ + ": " + description));
            }
            
            Gui.naplnCmb();
            
        } catch (Exception e) {
            System.out.println(e);
        }
    }
	
	static String filter_0 = "arp or icmp";
	
	public static Thread  port_0 = (new Thread(new Runnable() {
		
		PacketHandler ph_0 = new PacketHandler();
		public void run() {
			//System.out.println(alldevs_tmp.get(Gui.getDev_0sel()));
			ph_0.getPacket(alldevs_tmp.get(Gui.getDev_0sel()), filter_0, "0");
		}
	}));
	
	static String filter_1 = "arp or icmp";
	
	public static  Thread  port_1 = (new Thread(new Runnable() {
		
		PacketHandler ph_1 = new PacketHandler();
		public void run() {
			//System.out.println(alldevs_tmp.get(Gui.getDev_1sel()));
			ph_1.getPacket(alldevs_tmp.get(Gui.getDev_1sel()), filter_1, "1");
		}
	}));
	
	public static Thread  posielaj = (new Thread(new Runnable() {
		
		Posielanie psl = new Posielanie();
		public void run() {
			psl.PosliPacket();
		}
	}));

	public static boolean obshaujeMac(String mac) {
		for (RiadokTabulka riadok: macTabList) {
			if (riadok != null && riadok.getMacAdresa().equals(mac))
				return true;
		}
		
		return false;
	}
	
	public static int getCisloRiadku(String mac) {
		int index = -1;
		for (RiadokTabulka riadok: macTabList) {
			index++;
			
			if (riadok != null && riadok.getMacAdresa().equals(mac))
				return index;;
		}
		return -1;
	}
	
	public static void pridajZaznam(String mac, int port) {
		SwitchMain.macTabList.add(new RiadokTabulka(mac, port));
		//Gui.vypis(String.format("Pridany novy CAM zaznam:\n%s z portu %d\n", mac, port));
	}
	
	public static void odstranZaznam(String mac) {
		int n = 0;
		for (RiadokTabulka riadok: macTabList) {
			if (riadok != null && riadok.getMacAdresa().equals(mac))
				break;
			n++;
		}
		
		macTabList.remove(n);
	}
	
	public static void odstranZaznam(int index) {
		macTabList.remove(index);
	}
	
	public static int obsahujeMac(String mac) {
		for (RiadokTabulka riadok: macTabList) {
			if (riadok != null && riadok.getMacAdresa().equals(mac))
				return riadok.getPort();
		}
		return -1;
	}
	
	//funkcie na zistenie ci uz som dany packet posielal
	
	public static boolean obsahujePrijatePort_0_1(PcapPacket packet, int port) {
		if (port == 0) {
			for (PoslanyPacket pkt: prijatePort_0) {
				if (pkt != null && pkt.getPacket().toHexdump().equals(packet.toHexdump()))
					return true;
			}
			return false;
		}
		else if (port == 1){
			for (PoslanyPacket pkt: prijatePort_1) {
				if (pkt != null && pkt.getPacket().toHexdump().equals(packet.toHexdump()))
					return true;
			}
			return false;
		}
		
		return false;
	}
	
	public static void pridajDoPrijatePort_0_1(PcapPacket packet, int port) {
		PoslanyPacket pkt = new PoslanyPacket();
		pkt.setPacket(packet);
		
		if (port == 0)
			prijatePort_0.add(pkt);
		else if (port == 1)
			prijatePort_1.add(pkt);
		else
			System.out.println("to co mi davate?");
	}
	
	public static void odstranZPrijatePort_0_1(PcapPacket packet, int port) {
		int index = -1;
		if (port == 0) {
			for (PoslanyPacket pkt: prijatePort_0) {
				index++;
				if (pkt != null && pkt.getPacket().toHexdump().equals(packet.toHexdump()))
					break;
			}
			
			prijatePort_0.remove(index);
		}
		else if (port == 1) {
			for (PoslanyPacket pkt: prijatePort_1) {
				index++;
				if (pkt != null && pkt.getPacket().toHexdump().equals(packet.toHexdump()))
					break;
			}
			
			prijatePort_1.remove(index);
		}
		else 
			Gui.vypis("Chyba pri mazani z prijatych\n");
	}
	
	public static void pridajFilter_0(String text) {
		filter_0 = filter_0 + " and " + text;
		Gui.vypis("Aktualny filter pre port 0:\n" + filter_0 + "\n");
	}

	public static void pridajFilter_1(String text) {
		filter_1 = filter_1 + " and " + text;
		Gui.vypis("Aktualny filter pre port 1:\n" + filter_1 + "\n");
	}
	
}
