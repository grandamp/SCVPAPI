package org.keysupport.bc.scvp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.keysupport.bc.scvp.asn1.ServerPolicyRequest;
import org.keysupport.bc.scvp.asn1.ValPolRequest;

public class ServerPolicyClient {

	private static final Logger log = Logger.getLogger(ServerPolicyClient.class.getPackage().getName());
	private Provider jceProvider = null;
	private byte[] fullRequest = null;
	private byte[] fullResponse = null;

	public ServerPolicyClient(Provider jceProvider) {
		this.jceProvider = jceProvider;
	}

	public static void usage() {
		System.out.println("usage:  java -jar SCVPAPI.jar <scvp_url>");
	}

	public static void main(String args[]) throws SCVPException {

		/*
		 * We are going to override the platform logger for
		 * this example and throw all messages to the console.
		 */
		log.setUseParentHandlers(false);
		ConsoleHandler handler = new ConsoleHandler();
		log.setLevel(Level.ALL);
		handler.setLevel(Level.ALL);
		log.addHandler(handler);
		
		if (args.length <= 0) {
			usage();
			return;
		}
		Provider jceProvider = new BouncyCastleProvider();
		Security.addProvider(jceProvider);
		ServerPolicyClient client = new ServerPolicyClient(jceProvider);
		String scvpUrl = args[0];
		client.serverPolicyQuery(scvpUrl);
	}

	public ASN1OctetString generateNonce(int nonceSize) {
		SecureRandom random = null;
		byte[] nonce = null;
		nonce = new byte[nonceSize];
		random = new SecureRandom();
		random.nextBytes(nonce);
		return new DEROctetString(nonce);
	}

	public void serverPolicyQuery(String scvpServer) throws SCVPException {
		ValPolRequest policyRequest = new ValPolRequest(generateNonce(16));
		ServerPolicyRequest encapReq = new ServerPolicyRequest(policyRequest);
		log.log(Level.FINE, "ValPolRequest:\n" + ASN1Dump.dumpAsString(encapReq, true));
		byte[] rawReq;
		try {
			rawReq = encapReq.toASN1Primitive().getEncoded();
		} catch (IOException e) {
			throw new SCVPException("Problem with SCVP Policy Request", e);
		}
		this.fullRequest = rawReq;
		/*
		 * Send the request to the SCVP service...
		 */
		byte[] resp = sendSCVPRequestPOST(scvpServer, rawReq);
		this.fullResponse = resp;
		ASN1SequenceParser seqPar = null;
		if (resp != null) {
			ASN1StreamParser streamParser = new ASN1StreamParser(resp);
			Object object;
			try {
				object = streamParser.readObject();
			} catch (IOException e) {
				throw new SCVPException("Problem parsing response from server",
						e);
			}
			if (object instanceof ASN1SequenceParser) {
				seqPar = (ASN1SequenceParser) object;
				log.log(Level.FINE, "ValPolResponse:\n" + ASN1Dump.dumpAsString(seqPar, true));
			}
		}

	}

	/*
	 * This is not my preferable path... TODO: Replace transport with Apache
	 * HTTP client.
	 */
	public static byte[] sendSCVPRequestPOST(String postURL, byte[] req)
			throws SCVPException {
		byte[] resp = null;
		try {
			URL url = new URL(postURL);
			URLConnection con = url.openConnection();
			con.setReadTimeout(10000);
			con.setConnectTimeout(10000);
			con.setAllowUserInteraction(false);
			con.setUseCaches(false);
			con.setDoOutput(true);
			con.setDoInput(true);
			con.setRequestProperty("Content-Type",
					"application/scvp-vp-request");
			con.setRequestProperty("Accept",
					"application/scvp-vp-response");
			OutputStream os = con.getOutputStream();
			os.write(req);
			os.close();
			/*
			 * Lets make sure we are receiving an SCVP response...
			 */
			//if (con.getContentType().equalsIgnoreCase(
			//		"application/scvp-vp-response")) {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				byte[] chunk = new byte[4096];
				int bytesRead;
				InputStream stream = con.getInputStream();
				while ((bytesRead = stream.read(chunk)) > 0) {
					baos.write(chunk, 0, bytesRead);
				}
				resp = baos.toByteArray();
			//} else {
			//	throw new SCVPException(
			//			"Response from the server is not a CMS message");
			//}
		} catch (IOException e) {
			throw new SCVPException("Problem communicating with SCVP server", e);
		}
		return resp;
	}

	/**
	 * @return the fullRequest
	 */
	public byte[] getFullRequest() {
		return fullRequest;
	}

	/**
	 * @return the fullResponse
	 */
	public byte[] getFullResponse() {
		return fullResponse;
	}

}
