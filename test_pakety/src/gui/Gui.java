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
	static int count_arp, count_tcp, count_udp, count_icmp, count_raw, count_snap, count_unkw;
	static String[] stlpce = {" MAC adresa", "Port"};
	static JTable macTab;
	static DefaultTableModel tabModel; 
	
	static Object[][] macData = {};
	
	final static Border obrys= BorderFactory.createLineBorder(Color.black);
	
	public void gui() {
		
		win = new JFrame("Sw Switch");
		win.setLayout(null);
		win.setSize(800, 600);
		win.setVisible(true);
		win.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		win.setLocationRelativeTo(null);
		
		//arp
		count_arp = 0;
		l_arp = new JLabel("ARP:");
		l_arp.setBounds(5, 10, 35, 15);
		win.add(l_arp);
		
		n_arp = new JLabel();
		n_arp.setText(String.valueOf(count_arp));
		n_arp.setBounds(40, 10, 60, 15);
		win.add(n_arp);

		//tcp
		count_tcp = 0;
		l_tcp = new JLabel("TCP:");
		l_tcp.setBounds(5, 25, 35, 15);
		win.add(l_tcp);
		
		n_tcp = new JLabel();
		n_tcp.setText(String.valueOf(count_tcp));
		n_tcp.setBounds(40, 25, 60, 15);
		win.add(n_tcp);
		
		//udp
		count_udp = 0;
		l_udp = new JLabel("UDP:");
		l_udp.setBounds(5, 40, 35, 15);
		win.add(l_udp);
		
		n_udp = new JLabel();
		n_udp.setText(String.valueOf(count_udp));
		n_udp.setBounds(40, 40, 60, 15);
		win.add(n_udp);
				
		//icmp
		count_icmp = 0;
		l_icmp = new JLabel("ICMP:");
		l_icmp.setBounds(5, 55, 35, 15);
		win.add(l_icmp);
		
		n_icmp = new JLabel();
		n_icmp.setText(String.valueOf(count_icmp));
		n_icmp.setBounds(40, 55, 60, 15);
		win.add(n_icmp);
		
		//ostatne
		l_raw = new JLabel("RAW");
		l_snap = new JLabel("SNAP");
		l_llc = new JLabel("LLC");
		l_ipx = new JLabel("IPX");
		l_sap = new JLabel("SAP");
		
		//unkw
		count_unkw = 0;
		l_unkw = new JLabel("unkw:");
		l_unkw.setBounds(5, 70, 35, 15);
		win.add(l_unkw);
		
		n_unkw = new JLabel();
		n_unkw.setText(String.valueOf(count_unkw));
		n_unkw.setBounds(40, 70, 60, 15);
		win.add(n_unkw);
				
		textpane = new JTextPane();
		poleDoc = textpane.getStyledDocument();
		
		sBar = new JScrollPane(textpane);
		sBar.setBounds(win.getWidth() / 2, 5, win.getWidth() / 2 - 15, 2 * win.getHeight() / 3 - 40);
		sBar.setBorder(obrys);
		textpane.setEditable(false);
		win.add(sBar);
		
		//mac tab
		tabModel = new DefaultTableModel();
		tabModel.addColumn("MAC adresa");
		tabModel.addColumn("port");
		
		macTab = new JTable(tabModel);
		
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
	
	public static void incCount_arp() {
		count_arp += 1;
		n_arp.setText(String.valueOf(count_arp));
		obnov();
	}
	
	public static void incCount_tcp() {
		count_tcp += 1;
		n_tcp.setText(String.valueOf(count_tcp));
		obnov();
	}

	public static void incCount_udp() {
		count_udp += 1;
		n_udp.setText(String.valueOf(count_udp));
		obnov();
	}
	
	public static void incCount_icmp() {
		count_icmp += 1;
		n_icmp.setText(String.valueOf(count_icmp));
		obnov();
	}
	
	public static void incCount_unkw() {
		count_unkw += 1;
		n_unkw.setText(String.valueOf(count_unkw));
		obnov();
	}
	
	public static void pridajRiadok(String mac, int port) {
		
		tabModel.addRow(new Object[]{mac, port});
		tabModel.fireTableDataChanged();
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
		try {
			win.revalidate();
			win.repaint();
		}
		catch (Exception e) {
			// to je zle :D
		}
	}
}
