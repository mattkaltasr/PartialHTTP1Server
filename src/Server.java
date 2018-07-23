import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;


public class Server {

	private final static Path RECORDS = Paths.get("records.ser");

	private final static Path PASSWORDS = Paths.get("passwords.txt");

	public static void main(String[] args) {
		
		JFileChooser jfc = new JFileChooser(".");
		FileNameExtensionFilter filter = new FileNameExtensionFilter("JKS FILES", "jks");
		jfc.setDialogTitle("Open certificate file (server.jks)");
		jfc.setFileFilter(filter);
		int returnVal = jfc.showOpenDialog(null);
		if (returnVal == JFileChooser.APPROVE_OPTION) {
			File file = jfc.getSelectedFile();
			if (file == null) {
				return;
			}
			System.setProperty("javax.net.ssl.keyStore", file.getAbsolutePath());
			String password = JOptionPane.showInputDialog("Enter password for certificate:");
			if (password == null) {
				return;
			}
			System.setProperty("javax.net.ssl.keyStorePassword", password);
		} else {
			return;
		}

		Map<String, List<String>> records = loadRecords(); // If records file exists, load info, otherwise load
		// empty map (key is the title of group, value is the list of messages).

		Map<String, String> passwords = loadPasswords(); // Load database with logins/passwords.

		boolean run = true;

		SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();

		try (SSLServerSocket sslServerSocket = (SSLServerSocket)sslServerSocketFactory.createServerSocket(2222)) {
			System.out.println("Server is running on port 2222...");	

			while (run) {
				SSLSocket clientSocket = (SSLSocket) sslServerSocket.accept();
				System.out.println("Accepted client.");
				new Thread(new ClientListener(clientSocket, sslServerSocket)).start();
			} // while

		} catch (IOException e) {
			// Server stops.
			System.out.println("Server encountered a problem: invalid password or certificate");
		} finally {
			storeRecords(records);
			storePasswords(passwords);
			System.out.println("Server stopped.");
		}

	}

	static class ClientListener implements Runnable {

		private boolean run = true;

		private boolean authenticated;
		
		private String curuser;

		SSLSocket sslClientSocket;

		SSLServerSocket sslServerSocket;

		ClientListener(SSLSocket sslClientSocket, SSLServerSocket sslServerSocket) {
			this.sslClientSocket = sslClientSocket;
			this.sslServerSocket = sslServerSocket;
		}

		@Override
		public void run() {

			try (DataOutputStream dos = new DataOutputStream(sslClientSocket.getOutputStream())) {
				try (DataInputStream dis = new DataInputStream(sslClientSocket.getInputStream())) {
					while (run) {

						String msg = dis.readUTF();

							String items[] = msg.split("@");

							Command cmd = Command.valueOf(items[0]);

							switch (cmd) {

							case AUTH:
								if (items.length < 3) {
									dos.writeUTF("You must provide login and password");
									break;
								}
								String login = items[1];
								if (login.length() == 0) {
									dos.writeUTF("Login cannot be empty");
									break;
								}
								String pswrd = items[2];	
								if (pswrd.length() == 0) {
									dos.writeUTF("Password cannot be empty");
									break;
								}
								pswrd = getHashPassword(pswrd);
								Map<String, String> passwords = loadPasswords();
								if (passwords.containsKey(login)) {
									String storedPswrd = passwords.get(login);
									if (storedPswrd.equals(pswrd)) {
										authenticated = true;
										dos.writeUTF("Login success");	
										curuser = login;
									} else {
										dos.writeUTF("Invalid password");
									}
								} else {
									authenticated = true;
									passwords.put(login, pswrd);
									dos.writeUTF("A new client has been created successfully " + authenticated);	
									curuser = login;
								}
								storePasswords(passwords);
								break;							
							case GET:
								if (!authenticated) {
									dos.writeUTF("Authentication required");
								} else {
									if (items.length < 2) {
										dos.writeUTF("You must provide group name");
										break;
									}
									String group = items[1];
									Map<String, List<String>> records = loadRecords();
									List<String> msgs = records.get(group);
									if (msgs == null) {
										dos.writeUTF("No group");
									} else if (msgs.isEmpty()) {
										dos.writeUTF("No messages");
									} else {
										for (String m: msgs) {
											dos.writeUTF(m);
										}
									}
									storeRecords(records);
								}

								break;							
							case POST:
								if (!authenticated) {
									dos.writeUTF("Authentication required");
								} else {
									if (items.length < 3) {
										dos.writeUTF("You must provide group and message");
										break;
									}
									String group = items[1];
									if (group.trim().length() == 0) {
										dos.writeUTF("Group name cannot be empty");
										break;
									}
									String message = items[2];
									if (message.trim().length() == 0) {
										dos.writeUTF("Message cannot be empty");
									} else {
										Map<String, List<String>> records = loadRecords();
										List<String> msgs = records.get(group);
										if (msgs == null) { // If the group does not exist, create it.
											List<String> listMsgs = new ArrayList<>();
											listMsgs.add(message + " " + LocalDateTime.now(Clock.systemUTC()) + " by " + curuser);
											records.put(group, listMsgs);
											dos.writeUTF("A new group has been created successfully");
										} else { // If group exists.
											msgs.add(message + " " + LocalDateTime.now(Clock.systemUTC()) + " by " + curuser); // Just add message.
											dos.writeUTF("A new message has been added to the group");
										}	
										storeRecords(records);
									}
								}
								break;							
							case END:
								if (authenticated) {
									authenticated = false; // Ends the session with the server, does not exit
									// the client and should allow him to log back in.

									dos.writeUTF("Logout successful");
								} else {
									dos.writeUTF("Logout failed: you are not authenticated");
								}
								break;
							case EXIT:
								dos.writeUTF("Bye");
								run = false;
							} // switch

					} // while

					System.out.println("Client lost");
				} 
			} catch (IOException e) { // dataoutputstream
			}

			System.out.println("ClientListener exits.");
		} // run method

	} // static class

	@SuppressWarnings("unchecked")
	private static Map<String, List<String>> loadRecords() {
		if (Files.exists(RECORDS)) {
			try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(RECORDS.toFile()))) {
				return (Map<String, List<String>>)ois.readObject();
			} catch (IOException | ClassNotFoundException e) {
				System.err.println("Records file exists, but content is invalid: " + e);
				return new HashMap<>();
			}
		} else {
			return new HashMap<>();
		}
	}

	private static void storeRecords(Map<String, List<String>> records) {
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(RECORDS.toFile()))) {
			oos.writeObject(records);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static Map<String, String> loadPasswords() {
		Map<String, String> map = new HashMap<>();
		if (Files.exists(PASSWORDS)) {
			try {
				Files.readAllLines(PASSWORDS).forEach(l -> {
					String[] loginPassw = l.split(" ");
					map.put(loginPassw[0], loginPassw[1]);
				});
			} catch (IOException e) {
				System.err.println("Passwords file exists, but content is invalid: " + e);
			}
		}
		return map;

	}

	private static void storePasswords(Map<String, String> passwords) {
		StringBuilder sb = new StringBuilder();
		passwords.forEach((k, v) -> sb.append(k).append(" ").append(v).append("\r\n"));
		try {
			Files.write(PASSWORDS, sb.toString().getBytes());
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static String getHashPassword(String password) {

		try {

			// Generate salt.
			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
			sr.setSeed(1234565454565456l);
			byte salt[] = new byte[16];
			sr.nextBytes(salt);

			// Generate hash.
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, 512);
			SecretKey key = skf.generateSecret(spec);
			byte[] res = key.getEncoded();

			// To hexadecimal.
			BigInteger bi = new BigInteger(1, res);
			String hex = bi.toString(16);
			int paddingLength = res.length * 2 - hex.length();
			if (paddingLength > 0) {
				return String.format("%0" + paddingLength + "d", 0) + hex;
			} else {
				return hex;
			}

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return "falied";
		}

	}

}
