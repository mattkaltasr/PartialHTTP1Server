import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;

public class Client {
	
	private final static String MENU = "LOGIN\nGET\nPOST\nLOGOUT\nEXIT\n";

	public static void main(String[] args) throws KeyManagementException, NoSuchAlgorithmException, IOException {
		
		JFileChooser jfc = new JFileChooser(".");
		FileNameExtensionFilter filter = new FileNameExtensionFilter("JKS FILES", "jks");
		jfc.setDialogTitle("Open certificate file (client.jks)");
		jfc.setFileFilter(filter);
		int returnVal = jfc.showOpenDialog(null);
		if (returnVal == JFileChooser.APPROVE_OPTION) {
			File file = jfc.getSelectedFile();
			if (file == null) {
				return;
			}
			System.setProperty("javax.net.ssl.trustStore", file.getAbsolutePath());
			String password = JOptionPane.showInputDialog("Enter password for certificate:");
			if (password == null) {
				return;
			}
			System.setProperty("javax.net.ssl.trustStorePassword", password);
		} else {
			return;
		}

		SSLSocketFactory sslSocketFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();

		try (SSLSocket sslClientSocket = (SSLSocket)sslSocketFactory.createSocket(InetAddress.getByName("localhost"), 2222)) {
			
			sslClientSocket.startHandshake();

			try (DataOutputStream dos = new DataOutputStream(sslClientSocket.getOutputStream())) {
				
				try (DataInputStream dis = new DataInputStream(sslClientSocket.getInputStream())) {

					new Thread(new ServerListener(dis)).start();

					boolean run = true;

					try (Scanner sc = new Scanner (System.in)) {
						
						while (run) {
							Thread.sleep(1000);
							System.out.println(MENU);
							System.out.print("Enter command: ");
							String c = sc.nextLine().trim();
							if (c.equalsIgnoreCase("exit")) {
								dos.writeUTF("EXIT");
								run = false;
							} else if (c.equalsIgnoreCase("logout")) {
								dos.writeUTF("END");
							} else if (c.equalsIgnoreCase("GET")) {
								System.out.print("Enter group name: ");
								String group = sc.nextLine().trim();
								dos.writeUTF("GET@" + group);
							} else if (c.equalsIgnoreCase("POST")) {
								System.out.print("Enter group name: ");
								String group = sc.nextLine().trim();
								System.out.print("Enter message: ");
								String msg = sc.nextLine().trim();
								dos.writeUTF("POST@" + group + "@" + msg);
							} else if (c.equalsIgnoreCase("login")) {
								System.out.print("Enter login: ");
								String login = sc.nextLine().trim();
								System.out.print("Enter password: ");
								String passw = sc.nextLine().trim();
								dos.writeUTF("AUTH@" + login + "@" + passw);
							}
							else {
								System.out.println("Invalid command");
							}
						}
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			}
		} catch (IOException e) { // Server's certificate information does not match the expected information in the
			// client.
			
			System.out.println("Handshake failed: " + e);
		}

	}	

	static class ServerListener implements Runnable {

		boolean run = true;

		DataInputStream dis;

		ServerListener(DataInputStream dis) {
			this.dis = dis;
		}

		@Override
		public void run() {

			while (run) {

				try {
					String msg = dis.readUTF();
					System.out.println(msg);
				} catch (Exception exc) {
					run = false;
				}

			} // while

		} // run method

	} // static class

}
