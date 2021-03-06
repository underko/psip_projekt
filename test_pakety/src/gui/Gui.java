package gui;

import java.awt.Color;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.text.*;

import test_pakety.PacketCapturer;

public class Gui extends JFrame {
	
	static JFrame win;
	static JButton btn_tmpname;
	static JTextPane textpane;
	static JScrollPane sBar;	
	static JLabel l_arp, l_tcp, l_udp, l_icmp, l_raw, l_snap, l_llc, l_ipx,	l_sap, l_unkw;
	static StyledDocument poleDoc;
	static JComboBox<String> cmbDevices;
	
	
	final static Border obrys= BorderFactory.createLineBorder(Color.black);
	
	public void gui() {
		
		win = new JFrame("Sw Switch");
		win.setLayout(null);
		win.setSize(800, 600);
		win.setVisible(true);
		win.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		win.setLocationRelativeTo(null);
		
		l_arp = new JLabel("ARP");
		l_tcp = new JLabel("TCP");
		l_udp = new JLabel("UDP");
		l_icmp = new JLabel("ICMP");
		l_raw = new JLabel("RAW");
		l_snap = new JLabel("SNAP");
		l_llc = new JLabel("LLC");
		l_ipx = new JLabel("IPX");
		l_sap = new JLabel("SAP");
		l_unkw = new JLabel("UNKW");
		
		textpane = new JTextPane();
		poleDoc = textpane.getStyledDocument();
		
		sBar = new JScrollPane(textpane);
		sBar.setBounds(win.getWidth() / 3, 5, 2 * win.getWidth() / 3 - 15, win.getHeight() - 40);
		sBar.setBorder(obrys);
		textpane.setEditable(false);
		win.add(sBar);
		
		//cmbDevices = new JComboBox<String>((String[]) PacketCapturer.devArray.toArray());
		//cmbDevices.setBounds(5, 5, 130, 30);
		//cmbDevices.setSelectedIndex(0);		
		//win.add(cmbDevices);
		
		win.revalidate();
		win.repaint();
	}
	
	public static void vypis(String s) {
		try {
			poleDoc.insertString(poleDoc.getLength(), s, null);
			textpane.setCaretPosition(textpane.getDocument().getLength());
		} 
		catch (BadLocationException e) {
			e.printStackTrace();
		}
	}
}
