package switch_main;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;

import switch_gui.Gui;
import switch_workClasses.PacketHandler;
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
            
            for (PcapIf device: alldevs_tmp) {
                String description = (device.getDescription() != null) ? device.getDescription(): "No description available";
                System.out.printf("#%d: %s [%s]\n", ++i, device, description);
                Gui.cmbDevArr.add(description);
                //Gui.vypis(String.format("#%d: %s [%s]\n", i, device.toString(), description));
            }
            
            Gui.naplnCmb();
            
        } catch (Exception e) {
            System.out.println(e);
        }
        
    }
	
	static String filter_0 = "ip";
	
	public static Thread  port_0 = (new Thread(new Runnable() {
		
		PacketHandler ph_0 = new PacketHandler();
		public void run() {
				ph_0.getPacket(alldevs_tmp.get(Gui.getDev_0sel()), filter_0, "0");
		}
	}));
	
	static String filter_1 = "ip";
	
	public static  Thread  port_1 = (new Thread(new Runnable() {
		
		PacketHandler ph_1 = new PacketHandler();
		public void run() {
				ph_1.getPacket(alldevs_tmp.get(Gui.getDev_1sel()), filter_1, "1");
		}
	}));

	public static boolean obshaujeMac(String mac, int port) {
		for (RiadokTabulka riadok: macTabList) {
			if (riadok != null && riadok.getMacAdresa().equals(mac) && riadok.getPort() == port)
				return true;
		}
		
		return false;
	}
	
	public static void pridajZaznam(String mac, int port) {
		SwitchMain.macTabList.add(new RiadokTabulka(mac, port));
		Gui.vypis(String.format("Pridany novy CAM zaznam:\n%s z portu %d\n", mac, port));
	}
	
	public static int obsahujeMac(String mac) {
		for (RiadokTabulka riadok: macTabList) {
			if (riadok != null && riadok.getMacAdresa().equals(mac))
				return riadok.getPort();
		}
		return -1;
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
