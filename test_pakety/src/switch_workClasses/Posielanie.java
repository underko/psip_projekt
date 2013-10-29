package switch_workClasses;

import switch_main.SwitchMain;

public class Posielanie implements Runnable{

	@Override
	public void run() {
		// TODO Auto-generated method stub
		
	}
	
	@SuppressWarnings("static-access")
	public void PosliPacket() {
		while (true) {
			
			/*
			 	System.out.println(user + ": cyklus a mam poslat\nport 0: " + SwitchMain.quePort_0.size() + "\nport 1: " + SwitchMain.quePort_1.size() + "\ntmp: " + tmp);
        		posliPacket(user);
			 
			*/
			try {
				Thread.currentThread().sleep(5);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			if (!SwitchMain.quePort_0.isEmpty()) {
				PacketHandler.posliPacket("0");
			}
			if (!SwitchMain.quePort_1.isEmpty()) {
				PacketHandler.posliPacket("1");
			}
		}
	}

}
