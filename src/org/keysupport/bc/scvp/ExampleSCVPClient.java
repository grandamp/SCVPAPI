package org.keysupport.bc.scvp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.SignedDataParser;
import org.bouncycastle.asn1.x509.Certificate;
import org.keysupport.bc.scvp.asn1.CertChecks;
import org.keysupport.bc.scvp.asn1.SCVPRequest;

public class ExampleSCVPClient {

	public ExampleSCVPClient() {
		// TODO Auto-generated constructor stub
	}

	/*
	 * Temporary main method for testing.
	 */
	public static void main(String args[]) throws CertificateException, IOException {
		
		long start = System.currentTimeMillis();
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		String certFile = "/tmp/eeCert";
		X509Certificate endEntityCert = (X509Certificate) cf.generateCertificate(new FileInputStream(certFile));
		ByteArrayInputStream bais = new ByteArrayInputStream(endEntityCert.getEncoded());
		ASN1InputStream dis = new ASN1InputStream(bais);
		ASN1Primitive dobj = dis.readObject();
		dis.close();
		Certificate eCert = Certificate.getInstance(dobj);
		System.out.println(eCert.getSubject().toString());
		
		SCVPRequestBuilder builder = new SCVPRequestBuilder();
		/*
		 * We are forming a delegated path validation request, and
		 * we are not going to ask for any wantBack(s).  We are basically
		 * trusting the SCVP service to centrally validate our certificates.
		 */
		builder.addCertCheck(CertChecks.idStcBuildStatusCheckedPkcPath);
		/*
		 * We can override policy, but our SCVP testing service makes
		 * use of the Common Policy Root CA as the Trust Anchor.
		 */
		//builder.addTrustAnchors(trustAnchor);
		builder.setValidationPolRef(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.19.1"), null);
		/*
		 * Adding policy OIDs for OMB M-04-04 LOA-4:
		 * 
		 * http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-2.pdf#page=123
		 * 
		 * Where the OIDs are documented at:
		 * 
		 * http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/pki_registration.html
		 */
		builder.addUserPolicy(new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.13"));  //Common-Auth
		builder.addUserPolicy(new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.18"));  //PIVI-Auth
		builder.addUserPolicy(new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.26"));  //SHA1-Auth
		builder.addUserPolicy(new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.7"));  //Common-HW
		builder.addUserPolicy(new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.18"));  //PIVI-HW
		builder.addUserPolicy(new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.24"));  //SHA1-HW
		builder.addUserPolicy(new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.16"));  //Common-High
		builder.addUserPolicy(new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.12"));  //FBCA Medium-HW
		builder.addUserPolicy(new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.4"));  //FBCA High
		/*
		 * These are the additional RFC-5280 inputs:
		 * 
		 * We do not allow wild-card policy assertions (InhibitAnyPolicy).
		 * We require the policy oids to be present in all certs within the path (RequireExplicitPolicy).
		 * We allow mapped policies in place of the explicitly defined inital policy set.
		 */
		builder.setInhibitAnyPolicy(true);
		builder.setRequireExplicitPolicy(true);
		builder.setInhibitPolicyMapping(false);
		/*
		 * This is the certificate we are validating
		 */
		builder.addCertReference(eCert);
		/*
		 * This is based off of the GSA SCVP Request/Response Profile
		 */
		builder.setRequestorName("URN:ValidationService:TEST:SCVPExample");
		builder.setRequestorText("LOG;HI;MAJ;OTH;APP,HTTP://FOO.GOV/,-");
		/*
		 * Adding a 16 byte nonce
		 */
		builder.generateNonce(16);
		/*
		 * Final assembly of the request.
		 */
		SCVPRequest req = builder.buildRequest();
		byte[] rawReq = req.toASN1Primitive().getEncoded();
		/*
		 * Send the request to the SCVP service...
		 */
		byte[] resp = sendSCVPRequestPOST("https://foo.com/", rawReq);
		
		/*
		 * We will save off the request and response for analysis as we develop.
		 */
		bais.reset();
		FileOutputStream stream = new FileOutputStream("/tmp/request");
		try {
			stream.write(rawReq);
		} finally {
			stream.close();
		}
		bais.reset();
		stream = new FileOutputStream("/tmp/response");
		try {
			stream.write(resp);
		} finally {
			stream.close();
		}
		
		/*
		 * Now that we ca create a successful DPV request and receive a response
		 * from the service, we had better get to cracking on parsing the response
		 * and validating the signature!
		 */
		if (resp != null) {
			ASN1StreamParser streamParser = new ASN1StreamParser(resp); 
			Object object = streamParser.readObject(); 
			if (object instanceof ASN1SequenceParser) { 
				ASN1SequenceParser sequenceParser = (ASN1SequenceParser) object;
				ContentInfoParser contentInfoParser = new ContentInfoParser(sequenceParser); 
				ASN1ObjectIdentifier contentType = contentInfoParser.getContentType();
				if (CMSObjectIdentifiers.signedData.equals(contentType)) {
					object = streamParser.readObject();
					SignedDataParser sdParser = SignedDataParser.getInstance(object);
					System.out.println("This is signed data.");
				} else {
					//Error condition
				}
			} else { 
				//Error condition
			}
		} else {
			//Error condition
		}
		
		System.out.println("Finished in " + (System.currentTimeMillis() - start) + " milliseconds.");
		
	}
	
	/*
	 * This is not my preferable path...
	 * TODO:  Replace transport with Apache HTTP client
	 */
	public static byte[] sendSCVPRequestPOST(String postURL, byte[] req) {
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
			con.setRequestProperty("Content-Type","application/scvp-cv-request");
			OutputStream os = con.getOutputStream();
			os.write(req);
			os.close();
			/*
			 * Lets make sure we are receiving an SCVP response...
			 */
			if (con.getContentType().equalsIgnoreCase("application/scvp-cv-response")) {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				byte[] chunk = new byte[4096];
				int bytesRead;
				InputStream stream = con.getInputStream();
				while ((bytesRead = stream.read(chunk)) > 0) {
					baos.write(chunk, 0, bytesRead);
				}
				resp = baos.toByteArray();
			} else {
				//Error condition
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return resp;
	}

}
