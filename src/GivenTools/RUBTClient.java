//Sahil Kumbhani, srk112, 151003078 
//Andrew Cheng, ac1116, 150006800
package GivenTools;

import java.nio.ByteBuffer;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.net.*;

public class RUBTClient {
	static final String string = "012345678910ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	static SecureRandom random = new SecureRandom();
	static Socket cliSocket = null;
	static DataInputStream input_stream = null;
	static DataOutputStream output_stream = null;
	static boolean close = false;
	static boolean unchoked = true;
	static boolean firstRequest = true;
	static boolean haveMessage = false;
	
	/*
	 * the run method takes in the torrent file as an argument, converts the contents into
	 * a byte array. We then make a torrent info object in order to get the metadata of the .torrent file
	 * We parse the metadata information and make the url for the getRequest.
	 * We then capture the tracker response, and decode it to get the list of peers.
	 * Then
	*/
	private  static void run(String filename){
		File torrFile = null;
		torrFile = new File(filename);
		byte[] torrent_file_bytes = new byte[(int)torrFile.length()];
		
		try {
			FileInputStream input = new FileInputStream(torrFile);
			input.read(torrent_file_bytes);
			
			try {
				TorrentInfo ti = new TorrentInfo(torrent_file_bytes);
				Bencoder2 bc = new Bencoder2();
				String announceURL = ti.announce_url.toString();
				ByteBuffer infohash = ti.info_hash;
				
				byte[] infoHash = new byte[infohash.remaining()];
				infohash.get(infoHash);
				String info_hash = URLEncoder.encode(convertToHex(infoHash), "UTF-8");
				byte[] ih = info_hash.getBytes();
				String info_Hash = addPercent(info_hash);
				
				String peer_id = peerGenerator();
				byte[] peerid= peer_id.getBytes();
				
				int port = 6881;
				int uploaded = 0;
				int downloaded = 0;
				int left = ti.file_length;
				
				String event = "started";
				byte[] tracker_response = null;
				while (port < 6890){
					String url_name = appendUrl(announceURL,info_Hash, peer_id, port, uploaded, downloaded,left,event);
					tracker_response = getRequest(url_name);
					if (tracker_response == null){
						port++;
					}
					else{
						break;
					}
				}
				
				HashMap<ByteBuffer, Object> tracker_decoded = null;
				tracker_decoded = (HashMap<ByteBuffer, Object>) Bencoder2.decode(tracker_response);
				// ToolKit.print(tracker_decoded);
				
				ArrayList<Object> listofPeers = (ArrayList<Object>) tracker_decoded.get(ByteBuffer.wrap(new byte[]{'p','e','e','r','s'}));
				HashMap<ByteBuffer, Object> eachPeer = (HashMap<ByteBuffer, Object>) listofPeers.get(0);
				String peerip = new String(((ByteBuffer)eachPeer.get(ByteBuffer.wrap(new byte[] {'i','p'}))).array());
				int peerPort = (int) (eachPeer.get(ByteBuffer.wrap(new byte[]{'p','o','r','t'})) );
				
				if ((peerip.equals("172.16.97.11")) && (peerPort==26869)){
					cliSocket = new Socket(peerip, peerPort);
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else{
					System.out.println("No proper peer to connect to.");
				}
				
				byte[] handShake = handShake(infoHash, peerid).array();
				output_stream.write(handShake);
				output_stream.flush();
				
				byte[] peer_response = new byte[68];
				input_stream.read(peer_response);
				boolean hash_same = false;
				
				for (int i = 0; i < 48; i++){
					if (handShake[i] == peer_response[i]){
						if (i == 47){
							hash_same = true;
						}
						continue;
					}
					else{
						System.out.println("Not the same info-hash.");
						cliSocket.close();
						input_stream.close();
						output_stream.close();
					}
				}
				
				sendInterested();
				if (unchoked == true){
					System.out.println("You have been unchocked.");
				}
				
				while (isUnchoked()){
					//requestPieces();
					byte[] peer_msg = getPeerMsg();
					byte[] have_msg = messageCreator(4);
					byte[] index = new byte[4];
					haveMessage = true;
					
					for (int x = 0; x < 5; x++){
						if (!(peer_msg[x] == have_msg[x])){
							haveMessage = false;
							break;
						}
					}
					if (haveMessage){
						for (int y = 0; y < 4; y++){
							index[y] = peer_msg[y + 5];
						}
						System.out.println("They have a piece.");
						break;
					}
				}
				
				cliSocket.close();
				input_stream.close();
				output_stream.close();
			}catch (BencodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			input.close();
		}catch (FileNotFoundException e) {
			System.out.println("Error in opening torrent file: " + torrFile);
		}catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	/*
	 * this method keeps sending an interested message to the peer
	 * until the peer returns an unchoked message
	 */
	private static void sendInterested() throws IOException{
		byte[] interested = messageCreator(2);
		byte[] peermsg = new byte[200];
		byte[] unchoke = messageCreator(1);
		cliSocket.setSoTimeout(120000);
		
		while (true){
			try {
				output_stream.write(interested);
				output_stream.flush();
				input_stream.read(peermsg);
				unchoked = true;
				
				for (int i = 0; i < 5; i++){
					if (!(peermsg[i] == unchoke[i])){
						unchoked = false;
					}
				}
				if (unchoked){
					break;
				}
			}catch (SocketTimeoutException e){
				System.out.println("Peer did not respond within two minutes."); 
				break;
			}
		}
	}
	
	/*
	 * this method retrieves a message from the peer and 
	 * returns the message as a byte array
	 */
	private static byte[] getPeerMsg() throws IOException{
		int len = input_stream.readInt();
		byte[] peermsg = new byte[len];
		
		try {
			cliSocket.setSoTimeout(120000);
			input_stream.readFully(peermsg, 0, len);
			cliSocket.setSoTimeout(0);
		}catch (SocketTimeoutException e){
			System.out.println("Took too long to respond");
		}
		
		return peermsg;
	}
	
	/*
	 * This method checks to see if the peer sends
	 * a choked message. Returns false if peer chokes.
	 * Else return true
	 */
	private static boolean isUnchoked() throws IOException{
		byte[] peermsg = new byte[200];
		byte[] unchoke = messageCreator(1);
		unchoked = true;
		input_stream.read(peermsg);
		
		for (int z = 0; z < 5; z++){
			if (!(peermsg[z] == unchoke[z])){
				unchoked = false;
			}
		}
		if (unchoked){
			System.out.println("No one is choking.");
		}
		return unchoked;
	}
	
	/*
	 * This method creates the different messages that will be 
	 * sent to the peer. Returns message as byte array
	 */
	private static byte[] messageCreator(int ID){
		ByteBuffer msg;
		switch(ID){
			case 0:
				msg = ByteBuffer.allocate(5);
				msg.putInt(1);
				msg.put((byte)ID);
				break;
			case 1:
				msg = ByteBuffer.allocate(5);
				msg.putInt(1);
				msg.put((byte)ID);
				break;
			case 2:
				msg	= ByteBuffer.allocate(5);
				msg.putInt(1);
				msg.put((byte)ID);
				break;
			case 3:
				msg = ByteBuffer.allocate(5);
				msg.putInt(1);
				msg.put((byte)ID);
				break;
			case 4:
				msg = ByteBuffer.allocate(5);
				msg.putInt(5);
				msg.put((byte)ID);
				break;
			case 6:
				msg = ByteBuffer.allocate(17);
				msg.putInt(13);
				msg.put((byte)ID);
				break;
			default:
				return null;
		}
		return msg.array();
	}
	
	/* public static boolean checkConnection(){
		if (cliSocket == null){
			return false;
		}
		return cliSocket.isConnected();
	} */
	
	/* public static boolean checkClosed(){
		if (cliSocket == null){
			return true;
		}
		return cliSocket.isClosed();
	} */
	
	/* public static void closeConnection() throws IOException{
		if (input_stream != null){
			input_stream.close();
		}
		if (output_stream != null){
			output_stream.close();
		}
		if (cliSocket != null){
			cliSocket.close();
		}
	} */
	
	/*
	 * This method creates the handshake message that will
	 * be sent to the peer. Returns handshake as a ByteBuffer
	 */
	private static ByteBuffer handShake(byte[] infoHash, byte[] peerId){
		ByteBuffer handshake = ByteBuffer.allocate(68);
		final byte[] bt_protocol = new byte[] {'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't', ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};
		
		handshake.put((byte) 19);
		handshake.put(bt_protocol);
		handshake.putInt(0);
		handshake.putInt(0);
		handshake.put(infoHash);
		handshake.put(peerId);
		
		return handshake;
	}
	
	/*
	 * This method sends a message to the peer in order
	 * to request pieces to download
	 */
	private static void requestPieces(int index, int offset) throws IOException{
		byte[] request = messageCreator(6);
		ByteBuffer requestMessage = ByteBuffer.wrap(request);
		
		if (firstRequest == true){
			requestMessage.putInt(0);
			requestMessage.putInt(0);
			requestMessage.putInt(16384);
			firstRequest = false;
		}
		else{
			requestMessage.putInt(index);
			requestMessage.putInt(offset);
			requestMessage.putInt(16384);
		}
		output_stream.write(requestMessage.array());
		output_stream.flush();
	}
	
	/*
	 * randomly generates a peer id of length 20 bytes.
	 * Returns the peer id as a string
	 */
	private static String peerGenerator() {
		StringBuilder newString = new StringBuilder(20);
		
		for (int i = 0; i < 20; i++){
			newString.append(string.charAt(random.nextInt(string.length())));
		}
		
		return newString.toString();
	}
	
	/*
	 * converts the raw bytes of the info hash into a 
	 * hex string. Returns the info hash as a string
	 */
	private static String convertToHex(byte[] infoarray) {
		final StringBuilder build = new StringBuilder();
		
		for (byte b : infoarray){
			build.append(String.format("%02x", b));
		}
		
		return build.toString();
	}
	
	/*
	 * takes the hex string of the info hash and 
	 * adds a percent in order to fit the form
	 * of %nn. returns a string
	 */
	private static String addPercent(String infoHash){
		String temp = "";
		
		for (int i = 0; i < infoHash.length(); i++){
			temp += ("%" + (infoHash.substring(i, i + 2)));
			i++;
		}
		
		return temp;
	}
	
	/*
	 * appends all the necessary attributes into a URL string 
	 * in order to connect to the tracker
	 */
	private static String appendUrl(String announceURL, String infoHash, String peerID, int portNum, int uploaded, int downloaded, int left, String event ) {
		String appendedURL = announceURL + "?info_hash=" + infoHash + "&peer_id=" + peerID + "&port=" + portNum + "&uploaded=" + uploaded + "&downloaded=" + downloaded + "&left=" + left + "&event=" + event;
		return appendedURL;
	}
	
	/*
	 * this methods sends a get request with the URL string
	 * in which the response from the tracker will be returned
	 * as a byte array
	 */
	private static byte[] getRequest(String urlName){
		StringBuilder trackerResponse = new StringBuilder();
		
		try {
			URL urlTracker = new URL(urlName);
			HttpURLConnection trackerConn = (HttpURLConnection)urlTracker.openConnection();
			trackerConn.setRequestMethod("GET");
			BufferedReader inputStream = new BufferedReader(new InputStreamReader(trackerConn.getInputStream()));
			String s;
			
			while ((s = inputStream.readLine()) != null){
				trackerResponse.append(s);
			}
			inputStream.close();
		}catch (MalformedURLException e){
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (IOException e){
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return trackerResponse.toString().getBytes();
	}
	
	public static void main(String[] args){
		run(args[0]);
	}
}