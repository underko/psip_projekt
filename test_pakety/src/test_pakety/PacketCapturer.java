package test_pakety;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
 
public class PacketCapturer {
 
	public static ArrayList<String> devArray;
	public static PcapIf device_0 = new PcapIf();
	public static PcapIf device_1 = new PcapIf();
	
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

    
	@SuppressWarnings({ "unchecked", "rawtypes", "resource" })
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
            //String err = "";

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
            
            System.out.println("Vyberte 1. zariadenie: ");
            
            Scanner scan_n = new Scanner(System.in);
            Integer n = scan_n.nextInt();
            
            device_0 = alldevs_tmp.get(n - 1);
            

            System.out.println("Vyberte 2. zariadenie: ");
            
            scan_n = new Scanner(System.in);
            n = scan_n.nextInt();
            
            device_1 = alldevs_tmp.get(n - 1);
            
        } catch (Exception e) {
            System.out.println(e);
        }
        
        	port_0.start();
        	port_1.start();
        
        
    }
	
	static Thread  port_0 = (new Thread(new Runnable() {
		
		PacketHandler ph_0 = new PacketHandler();
		
		public void run() {
			
				ph_0.getPacket(device_0, "ip", "port_0");
			
		}
	}));
	
static Thread  port_1 = (new Thread(new Runnable() {
		
		PacketHandler ph_1 = new PacketHandler();
		
		public void run() {
			
				ph_1.getPacket(device_1, "ip", "port_1");
			
		}
	}));
	
}