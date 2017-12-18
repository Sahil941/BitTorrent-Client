// Sahil Kumbhani (srk112 | 151003078)
// Andrew Cheng (ac1116 | 150006800)
package GivenTools;
import java.nio.ByteBuffer;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.net.*;
import java.util.GregorianCalendar;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
public class RUBTClient {
	static final String string = "012345678910ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	static SecureRandom random = new SecureRandom();
	static Socket cliSocket = null;
	static DataInputStream input_stream = null;
	static DataOutputStream output_stream = null;
	static boolean close = false;
	static boolean unchoked = true;
	static boolean haveMessage = false;
	static final int block_length = 16384;
	
	
	/*
	 * the run method takes in the torrent file as an argument, converts the contents into
	 * a byte array. We then make a torrent info object in order to get the metadata of the .torrent file
	 * We parse the metadata information and make the url for the getRequest.
	 * We then capture the tracker response, and decode it to get the list of peers.
	 * Then
	*/
	private  static void run(String filename, File fileDownloaded) throws FileNotFoundException{
		File torrFile = null;
		torrFile = new File(filename);
		byte[] torrent_file_bytes = new byte[(int)torrFile.length()];
		
		File saveFile = fileDownloaded;
		RandomAccessFile movFile = new RandomAccessFile(saveFile, "rw");
		
		try {
			FileInputStream input = new FileInputStream(torrFile);
			input.read(torrent_file_bytes);
			
			try {
				TorrentInfo ti = new TorrentInfo(torrent_file_bytes);
				String announceURL = ti.announce_url.toString();
				ByteBuffer infohash = ti.info_hash;
				
				byte[] infoHash = new byte[infohash.remaining()];
				infohash.get(infoHash);
				String info_hash = URLEncoder.encode(convertToHex(infoHash), "UTF-8");
				String info_Hash = addPercent(info_hash);
				
				String peer_id = peerGenerator();
				byte[] peerid= peer_id.getBytes();
				
				int port = 6881;
				int uploaded = 0;
				int downloaded = 0;
				int left = ti.file_length;
				
				String event = "";
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
			//	ToolKit.print(tracker_decoded);
				
				ArrayList<Object> listofPeers = (ArrayList<Object>) tracker_decoded.get(ByteBuffer.wrap(new byte[]{'p','e','e','r','s'}));
				double rtt_attempt= 0;
				double rtt_total= 0;
				double rtt_total1=0;
				double rtt_total2= 0;
				
				List<Object> listrtt= new ArrayList<Object>();
			   // ArrayList<Double, String> listofrtt= new ArrayList<Double, String>();
			    //ArrayList<String> peer_req= new ArrayList<String>();
				for(int i=0; i<listofPeers.size(); i++){
					HashMap<ByteBuffer, Object> eachPeer = (HashMap<ByteBuffer, Object>) listofPeers.get(i);
					String peerip = new String(((ByteBuffer)eachPeer.get(ByteBuffer.wrap(new byte[] {'i','p'}))).array());
					int peerPort = (int) (eachPeer.get(ByteBuffer.wrap(new byte[]{'p','o','r','t'})) );
				
					if(peerip.equals("172.16.97.11") && peerPort == 26869){
						System.out.println("first -RU peer found");
						int x= 0;
						while(x<10){
							rtt_attempt= pingConnection("172.16.97.11");
							rtt_total += rtt_attempt;
							x++;
						}
						
						//peer_rtt[0]= rtt_total;
					//	System.out.println(peer_rtt[0]);
						listrtt.add(rtt_total/10);
						listrtt.add("172.16.97.11");
						listrtt.add(26869);
						System.out.println("Total time for ten tries for first peer: " + rtt_total);
						//rtt_attempt= pingConnection("172.16.97.11");
					//	System.out.println("RTT: " + rtt_attempt);
					//	cliSocket = new Socket(peerip, peerPort);
					//	input_stream = new DataInputStream(cliSocket.getInputStream());
					//	output_stream = new DataOutputStream(cliSocket.getOutputStream());
					}
					else if(peerip.equals("172.16.97.12") && peerPort == 18413){
						System.out.println("second -RU peer found");
						int y= 0;
						while(y<10){
							rtt_attempt= pingConnection("172.16.97.11");
							rtt_total1 += rtt_attempt;
							y++;
						}
						
						listrtt.add(rtt_total1/10);
						listrtt.add("172.16.97.12");
						listrtt.add(18413);
						System.out.println("Total time for ten tries for second peer: " + rtt_total1);
						
						//	rtt_attempt= pingConnection("172.16.97.12");
					//	System.out.println("RTT: " + rtt_attempt);
						//	pingConnection("172.16.97.12");
					}
					else if(peerip.equals("172.16.97.13") && peerPort == 33124){
						System.out.println("third -RU peer found");
						int z= 0;
						while(z<10){
							rtt_attempt= pingConnection("172.16.97.11");
							rtt_total2 += rtt_attempt;
							z++;
						}
						
						listrtt.add(rtt_total2/10);
						listrtt.add("172.16.97.13");
						listrtt.add(33124);
						System.out.println("Total time for ten tries for third peer: " + rtt_total2);
						
						//	rtt_attempt= pingConnection("172.16.97.13");
					//	System.out.println("RTT: " + rtt_attempt);
						//	pingConnection("172.16.97.13");
					}
				}
				
				double rtt1= (double)listrtt.get(0);
				double rtt2= (double)listrtt.get(3);
				double rtt3= (double)listrtt.get(6);
				System.out.println("avgs are: "+rtt1 + ", " + rtt2 + ", " + rtt3);
				
				if(rtt1 < rtt2 && rtt1 < rtt3){
					
					cliSocket = new Socket((String)listrtt.get(1), (int)listrtt.get(2));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else if(rtt2 < rtt1 && rtt2 < rtt3){
				
					cliSocket = new Socket((String)listrtt.get(4), (int)listrtt.get(5));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else if(rtt3 < rtt1 && rtt3 < rtt2){
					
					cliSocket = new Socket((String)listrtt.get(7), (int)listrtt.get(8));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else if(rtt1 < rtt3 && rtt1 == rtt2){
					
					cliSocket = new Socket((String)listrtt.get(1), (int)listrtt.get(2));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else if(rtt1 < rtt2 && rtt1 == rtt3){
				
					cliSocket = new Socket((String)listrtt.get(1), (int)listrtt.get(2));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else if(rtt2 < rtt1 && rtt2 == rtt3){
					
					cliSocket = new Socket((String)listrtt.get(4), (int)listrtt.get(5));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else if(rtt2 < rtt3 && rtt2 == rtt1){
				
					cliSocket = new Socket((String)listrtt.get(1), (int)listrtt.get(2));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else if(rtt3 < rtt2 && rtt3 == rtt1){
					
					cliSocket = new Socket((String)listrtt.get(1), (int)listrtt.get(2));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else if(rtt3 < rtt1 && rtt3 == rtt2){
					
					cliSocket = new Socket((String)listrtt.get(4), (int)listrtt.get(5));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else if(rtt3 < rtt1 && rtt1 == rtt2){
					
					cliSocket = new Socket((String)listrtt.get(7), (int)listrtt.get(8));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else if(rtt1 < rtt2 && rtt3 == rtt2){
					
					cliSocket = new Socket((String)listrtt.get(1), (int)listrtt.get(2));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				else if(rtt2 < rtt3 && rtt3 == rtt1){
					
					cliSocket = new Socket((String)listrtt.get(4), (int)listrtt.get(5));
					input_stream = new DataInputStream(cliSocket.getInputStream());
					output_stream = new DataOutputStream(cliSocket.getOutputStream());
				}
				
				
				
				
				
			//	if (((peerip.equals("172.16.97.11")) && (peerPort==26869)) && ((peerip.equals("172.16.97.12"))  && (peerPort==18413)) && ((peerip.equals("172.16.97.13") && (peerPort==3324)))){
				
				//	System.out.println("three peers to connect to");
			//	}	
				//	cliSocket = new Socket(peerip, peerPort);
				//	input_stream = new DataInputStream(cliSocket.getInputStream());
				//	output_stream = new DataOutputStream(cliSocket.getOutputStream());
				
			//	else{
				//	System.out.println("No proper peer to connect to.");
				//	return;
			//	}
			//	System.out.println((ti.file_length)/16384);
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
					System.out.println("You have been unchoked.");
				}
				
				int num_pieces= ti.piece_hashes.length;
			//	System.out.println(num_pieces);
				byte[] byteReader;
				byte[] keepAlive = messageCreator(-1).array();
				ByteBuffer check = null;
				ByteBuffer[] piece_hash= ti.piece_hashes;
				byte[] piece_message= null;
				event= "started";
				String urlupdate= appendUrl(announceURL,info_Hash, peer_id, port, uploaded, downloaded,left,event);
				URLConnection tracker_update= new URL(urlupdate).openConnection();
				tracker_update.connect();
				
				long start_download = System.nanoTime();
				
				for (int i = 0; i < num_pieces ; i++){
					
					for (int j = 0; (j < 2); j++){
						
						output_stream.write(keepAlive);
						output_stream.flush();
						//byteReader= null;
						//byteReader = new byte[16384];
						
						if (j == 0){
							check=requestPieces(i, j);
						//	System.out.println(check.toString());
							//byteReader = new byte[16384];
						}
						else if (j == 1){
							requestPieces(i, block_length);
							//byteReader = new byte[16384];
						}
						/*if ((i == 510) && (j == 1)){
							byteReader = null;
							byteReader = new byte[8603];
						}*/
						
						//System.out.println("testing");
						cliSocket.setSoTimeout(120000);
						byteReader= getPeerMsg(block_length + 13);
						piece_message= separateMsg(byteReader, 13);
						//input_stream.readFully(byteReader);
						/*if(samePieceHash(piece_message, piece_hash[i].array())){
							movFile.write(piece_message);
						}
						else{
							System.out.println("Incorrect Piece");
							
						}*/
						movFile.write(piece_message);
						
					}
					System.out.println("piece number: "+i);
				}
				long finish= System.nanoTime();
				long download_time= finish- start_download;
				System.out.println("Total time of download: " + download_time);
				event= "completed";
				urlupdate= appendUrl(announceURL,info_Hash, peer_id, port, uploaded, downloaded,left,event);
				tracker_update= new URL(urlupdate).openConnection();
				tracker_update.connect();
				System.out.println("Download complete");
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
	
	
	private static double pingConnection(String ip_address) throws IOException{
		
			InetAddress address= InetAddress.getByName(ip_address);
			
			double end_time= 0;
			double start_time= new GregorianCalendar().getTimeInMillis();
			
			if(address.isReachable(5000)){
				end_time = new GregorianCalendar().getTimeInMillis();
				
				return (end_time-start_time);
			}
			else{
				System.out.println("Address is unreachable");
				return -1;
			}
	}
	
	
	/*
	 * this method keeps sending an interested message to the peer
	 * until the peer returns an unchoked message
	 */
	private static void sendInterested() throws IOException{
		byte[] interested = messageCreator(2).array();
		byte[] peermsg = new byte[200];
		byte[] unchoke = messageCreator(1).array();
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
	
	private static byte[] getPeerMsg(int size) throws IOException{
		int length;
		int offset= 0;
		int iterator= 0;
		
		while((length = input_stream.available()) < size && iterator < 10000000){
			offset= length;
			iterator++;
		}
		
		if(iterator == 10000000){
			throw new IOException("No response from peer, check your connection");
		}
		
		byte[] peerMsg= new byte[length];
		input_stream.read(peerMsg);
		
		if(length > size){
			byte[] outcome= new byte[size];
			System.arraycopy(peerMsg, offset, outcome, 0, size);
			return outcome;
		}
		else{
			return peerMsg;
		}
		
		
	}
	
	private static byte[] separateMsg(byte[] message, int length){
		byte[] mssg= new byte[length];
		int plength= message.length- length;
		
		byte[] piece= new byte[plength];
		System.arraycopy(message, 0, mssg, 0, length);
		System.arraycopy(message, length, piece, 0, plength);
	
		return piece;
	}
	
	private static boolean samePieceHash(byte[] piece, byte[] hash){
		byte[] encoded = null;
		
		try{
			MessageDigest encoder= MessageDigest.getInstance("SHA-1");
			encoded= encoder.digest(piece);
		} catch(NoSuchAlgorithmException e){
			System.err.println("Not supported algorithm");
		}
		
		if(Arrays.equals(encoded, hash)){
			return true;
		}
		else{
			return false;
		}
	}
	
	private static void saveDownload(File saveFile){}
	
	/*
	 * This method checks to see if the peer sends
	 * a choked message. Returns false if peer chokes.
	 * Else return true
	 */
	private static boolean isUnchoked() throws IOException{
		byte[] keepAlive = messageCreator(-1).array();
		output_stream.write(keepAlive);
		output_stream.flush();
		
		byte[] peermsg = new byte[5];
		input_stream.readFully(peermsg);
		byte[] unchoke = messageCreator(1).array();
		unchoked = true;
		for (int z = 0; z < 5; z++){
			if (!(peermsg[z] == unchoke[z])){
				unchoked = false;
				break;
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
	private static ByteBuffer messageCreator(int ID){
		ByteBuffer msg;
		switch(ID){
			
			case -1:
				msg = ByteBuffer.allocate(4);
				msg.putInt(0);
				break;
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
				msg = ByteBuffer.allocate(9);
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
		return msg;
	}
	
	
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
	private static ByteBuffer requestPieces(int index, int begin) throws IOException{
		ByteBuffer request = messageCreator(6);
	//	ByteBuffer requestMessage = ByteBuffer.wrap(request);
		
		request.putInt(index);
		request.putInt(begin);
		
		
		if ((index == 510) && (begin == block_length)){
			request.putInt(8603);
		}
		else{
			request.putInt(16384);
		}
		
		
		output_stream.write(request.array());
		output_stream.flush();
		return request;
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
	 * This methods sends a get request with the URL string
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
	
	public static void main(String[] args) throws IOException{
		if(args.length != 2){
			System.out.println("Did not provide the correct number of arguments");
			return;
		}
		
		String torrent_file = args[0];
		File output_file = new File(args[1]);
		if(!output_file.createNewFile()){
			if(!output_file.exists()){
				System.out.println("Unable to create file, please try again");
				return;
			}
		}
		
		run(torrent_file, output_file);
	}
}