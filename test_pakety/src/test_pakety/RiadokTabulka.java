package test_pakety;

public class RiadokTabulka {
	
	int port;
	String macAdresa;
	
	public RiadokTabulka(String mac, int port) {
		this.macAdresa = mac;
		this.port = port;
	}
	
	public RiadokTabulka() {
		// TODO Auto-generated constructor stub
	}

	public int getPort() {
		return port;
	}
	
	public void setPort(int port) {
		this.port = port;
	}
	
	public String getMacAdresa() {
		return macAdresa;
	}
	
	public void setMacAdresa(String macAdresa) {
		this.macAdresa = macAdresa;
	}

}
