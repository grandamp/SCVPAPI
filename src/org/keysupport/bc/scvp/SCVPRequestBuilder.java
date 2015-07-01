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
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.keysupport.bc.scvp.asn1.CVRequest;
import org.keysupport.bc.scvp.asn1.CertChecks;
import org.keysupport.bc.scvp.asn1.CertReferences;
import org.keysupport.bc.scvp.asn1.PKCReference;
import org.keysupport.bc.scvp.asn1.Query;
import org.keysupport.bc.scvp.asn1.SCVPRequest;
import org.keysupport.bc.scvp.asn1.TrustAnchors;
import org.keysupport.bc.scvp.asn1.UserPolicySet;
import org.keysupport.bc.scvp.asn1.ValidationPolRef;
import org.keysupport.bc.scvp.asn1.ValidationPolicy;

import sun.misc.IOUtils;

public class SCVPRequestBuilder {

	/*
	 * The core of the request
	 */
	private SCVPRequest encapRequest = null;
	private CVRequest request = null;
	private Query query = null;
	private ValidationPolicy validationPolicy = null;
	/*
	 * ValidationPolicy Contents
	 */
	private ValidationPolRef validationPolRef = null;
	private UserPolicySet initialPolicies = null;
	private ASN1Boolean inhibitAnyPolicy = null;
	private ASN1Boolean requireExplicitPolicy = null;
	private ASN1Boolean inhibitPolicyMapping = null;
	private TrustAnchors anchors = null;
	/*
	 * Query Contents
	 */
	private CertChecks checks = null;
	private CertReferences queriedCerts = null;
	/*
	 * CVRequest Contents
	 */
	private GeneralName requestorName = null;
	private DERUTF8String requestorText = null;
	private ASN1OctetString requestNonce = null;
	
	public SCVPRequestBuilder() {
		//Create a null instance of our class...
		//Then build (and encapsulate) the request manually using setters
	}
	
	public void setCertChecks(CertChecks checks) {
		this.checks = checks;
	}
	
	public void addCertCheck(ASN1ObjectIdentifier check) {
		if (this.checks != null) {
			this.checks.addObj(check);
		} else {
			this.checks = new CertChecks();
			this.checks.addObj(check);
		}
	}

	public void setTrustAnchors(TrustAnchors anchors) {
		this.anchors = anchors;
	}
	
	public void addTrustAnchor(Certificate cert) {
		if (this.anchors != null) {
			this.anchors.addTrustAnchor(new PKCReference(cert));
		} else {
			this.anchors = new TrustAnchors();
			this.anchors.addTrustAnchor(new PKCReference(cert));
		}
	}
	
	public void setValidationPolRef(ASN1ObjectIdentifier valPolId, ASN1Object valPolParams) {
		this.validationPolRef = new ValidationPolRef(valPolId, valPolParams);
	}

	public void setUserPolicySet(UserPolicySet initialPolicies) {
		this.initialPolicies = initialPolicies;
	}

	public void addUserPolicy(ASN1ObjectIdentifier policy) {
		if (initialPolicies != null) {
			initialPolicies.addObj(policy);
		} else {
			initialPolicies = new UserPolicySet();
			initialPolicies.addObj(policy);
		}
	}
	
	public void setInhibitAnyPolicy(boolean inhibit) {
		this.inhibitAnyPolicy = ASN1Boolean.getInstance(inhibit);
	}

	public void setRequireExplicitPolicy(boolean require) {
		this.requireExplicitPolicy = ASN1Boolean.getInstance(require);
	}

	public void setInhibitPolicyMapping(boolean inhibit) {
		this.inhibitPolicyMapping = ASN1Boolean.getInstance(inhibit);
	}

	public void setCertReferences(CertReferences queriedCerts) {
		this.queriedCerts = queriedCerts;
	}

	public void addCertReference(Certificate cert) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(cert);
		
		if (this.queriedCerts != null) {
			this.queriedCerts.addReference(new DERSequence(v), CertReferences.pkcRefs);
		} else {
			this.queriedCerts = new CertReferences();
			this.queriedCerts.addReference(new DERSequence(v), CertReferences.pkcRefs);
		}
	}
	
	//TODO:  Create another class based on GSA profile formula
	public void setRequestorName(String reqName) {
		this.requestorName = new GeneralName(6, reqName);
	}

	//TODO: Create another class based on GSA profile formula
	public void setRequestorText(String reqText) {
		this.requestorText = new DERUTF8String(reqText);
	}

	public void generateNonce(int nonceSize) {
		SecureRandom random = null;
		byte[] nonce = null;
		nonce = new byte[nonceSize];
		random = new SecureRandom();
		random.nextBytes(nonce);
		this.requestNonce = new DEROctetString(nonce);
	}

	public SCVPRequest buildRequest() {
		/*
		 * Start by building the ValidationPolicy per the setters called.
		 */
		
		validationPolicy = new ValidationPolicy(validationPolRef, null, initialPolicies,
				inhibitPolicyMapping, requireExplicitPolicy, inhibitAnyPolicy, anchors, null, null, null);
		/*
		 * Next, we build the Query with the settings called, adding the ValidationPolicy.
		 */
		query = new Query(queriedCerts, checks, null, validationPolicy, null, null, null, null,
				null, null, null);
		/*
		 * Now we construct the CVRequest, and add the Query.
		 */
		request = new CVRequest(query, null, requestNonce, requestorName, null, null, null, null, requestorText);
		/*
		 * Finally, we envelope the CVRequest in a CMS message and return to the caller.
		 */
		encapRequest = new SCVPRequest(SCVPRequest.idCtScvpCertValRequest, request);
		return encapRequest;
	}
	
	/*
	 * Temporary main method for testing.
	 */
	public static void main(String args[]) throws CertificateException, IOException {
		
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
		builder.addCertCheck(CertChecks.idStcBuildStatusCheckedPkcPath);
		//builder.addTrustAnchors(trustAnchor);
		builder.setValidationPolRef(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.19.1"), null);
		builder.addUserPolicy(new ASN1ObjectIdentifier("2.16.840.1.101.3.2.1.3.13"));
		builder.setInhibitAnyPolicy(true);
		builder.setRequireExplicitPolicy(true);
		builder.setInhibitPolicyMapping(false);
		builder.addCertReference(eCert);
		builder.setRequestorName("URN:ValidationService:TEST:SCVPExample");
		builder.setRequestorText("LOG;HI;MAJ;OTH;APP,HTTP://FOO.GOV/,-");
		builder.generateNonce(16);
		SCVPRequest req = builder.buildRequest();
		byte[] rawReq = req.toASN1Primitive().getEncoded();
		byte[] resp = builder.sendSCVPRequestPOST("REMOVED", rawReq);
		
		bais.reset();
		FileOutputStream stream = new FileOutputStream("/tmp/request");
		try {
			stream.write(rawReq);
		} finally {
			stream.close();
		}
		
		System.out.println("fin");
		
	}
	
	public byte[] sendSCVPRequestPOST(String postURL, byte[] req) {
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
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] chunk = new byte[4096];
			int bytesRead;
			InputStream stream = con.getInputStream();
			while ((bytesRead = stream.read(chunk)) > 0) {
				baos.write(chunk, 0, bytesRead);
			}
			resp = baos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return resp;
	}

}
