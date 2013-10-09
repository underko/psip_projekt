package gui;

import java.awt.Color;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.*;

@SuppressWarnings("serial")
public class Gui extends JFrame {
	
	static JFrame win;
	static JButton btn_tmpname;
	static JTextPane textpane;
	static JScrollPane sBar, macBar;	
	static JLabel l_arp, l_tcp, l_udp, l_icmp, l_raw, l_snap, l_llc, l_ipx,	l_sap, l_unkw;
	static JLabel n_arp, n_tcp, n_udp, n_icmp, n_raw, n_snap, n_llc, n_ipx,	n_sap, n_unkw;
	static StyledDocument poleDoc;
	static JComboBox<String> cmbDevices;
	static int count_tcp, count_icmp;
	static String[] stlpce = {" MAC adresa", "Port"};
	static JTable macTab;
	static DefaultTableModel tabModel; 
	
	static Object[][] tmp_data= {{"mac tmp 01", new Integer(10)}, {"mac tmp 02", new Integer(20)}, {"mac tmp 03", new Integer(30)}, {"mac tmp 04", new Integer(40)}, {"mac tmp 05", new Integer(50)}};
	
	final static Border obrys= BorderFactory.createLineBorder(Color.black);
	
	public void gui() {
		
		win = new JFrame("Sw Switch");
		win.setLayout(null);
		win.setSize(800, 600);
		win.setVisible(true);
		win.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		win.setLocationRelativeTo(null);
		
		l_arp = new JLabel("ARP");

		count_tcp = 0;
		l_tcp = new JLabel("TCP:");
		l_tcp.setBounds(5, 5, 35, 15);
		//l_tcp.setBorder(obrys);
		win.add(l_tcp);
		
		n_tcp = new JLabel();
		n_tcp.setText(String.valueOf(count_tcp));
		n_tcp.setBounds(40, 5, 60, 15);
		//n_tcp.setBorder(obrys);
		win.add(n_tcp);
		
		l_udp = new JLabel("UDP");
		
		l_icmp = new JLabel("ICMP");
		
		count_icmp = 0;
		l_icmp = new JLabel("ICMP:");
		l_icmp.setBounds(5, 25, 35, 15);
		//l_icmp.setBorder(obrys);
		win.add(l_icmp);
		
		n_icmp = new JLabel();
		n_icmp.setText(String.valueOf(count_icmp));
		n_icmp.setBounds(40, 25, 60, 15);
		//n_icmp.setBorder(obrys);
		win.add(n_icmp);
		
		
		l_raw = new JLabel("RAW");
		l_snap = new JLabel("SNAP");
		l_llc = new JLabel("LLC");
		l_ipx = new JLabel("IPX");
		l_sap = new JLabel("SAP");
		l_unkw = new JLabel("UNKW");
		
		textpane = new JTextPane();
		poleDoc = textpane.getStyledDocument();
		
		sBar = new JScrollPane(textpane);
		sBar.setBounds(win.getWidth() / 2, 5, win.getWidth() / 2 - 15, 2 * win.getHeight() / 3 - 40);
		sBar.setBorder(obrys);
		textpane.setEditable(false);
		win.add(sBar);
		
		tabModel = new DefaultTableModel();
		macTab = new JTable(tmp_data, stlpce);
		
		sBar = new JScrollPane(macTab);
		sBar.setBounds(win.getWidth() / 2, 2 * win.getHeight() / 3 - 10, win.getWidth() / 2 - 15, win.getHeight() / 3 - 40);
		sBar.setBorder(obrys);
		
		win.add(sBar);
		
		obnov();
	}
	
	public int getCount_tcp() {
		return count_tcp;
	}

	public void setCount_tcp(int count_tcp) {
		Gui.count_tcp = count_tcp;
	}
	
	public static void incCount_tcp() {
		count_tcp += 1;
		n_tcp.setText(String.valueOf(count_tcp));
		obnov();
	}

	public static void incCount_icmp() {
		count_icmp += 1;
		n_icmp.setText(String.valueOf(count_icmp));
		obnov();
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
	
	public static void obnov() {
		win.revalidate();
		win.repaint();
	}
}
