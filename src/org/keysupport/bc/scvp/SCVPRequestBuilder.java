package org.keysupport.bc.scvp;

import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
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

public class SCVPRequestBuilder {

	private SCVPRequest encapRequest = null;
	private CVRequest request = null;
	private Query query = null;

	private CertChecks checks = null;
	private TrustAnchors anchors = null;
	private ValidationPolRef validationPolRef = null;
	private UserPolicySet initialPolicies = null;
	private ASN1Boolean inhibitAnyPolicy = null;
	private ASN1Boolean requireExplicitPolicy = null;
	private ASN1Boolean inhibitPolicyMapping = null;
	private CertReferences queriedCerts = null;
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
		if (this.queriedCerts != null) {
			this.queriedCerts.addReference(cert, CertReferences.pkcRefs);
		} else {
			this.queriedCerts = new CertReferences();
			this.queriedCerts.addReference(cert, CertReferences.pkcRefs);
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
		//Going to rely on the developer to call the minimal setters (some can be null)
		
		//setCertCheck(CvCheckOid.idStcBuildStatusCheckedPkcPath);
		//addTrustAnchors(trustAnchor);
		//setValidationPolRef("1.3.6.1.5.5.7.19.1");
		//addUserPolicy("2.16.840.1.101.3.2.1.3.13");
		//setInhibitAnyPolicy(true);
		//setRequireExplicitPolicy(true);
		//setInhibitPolicyMapping(false);
		//addQueriedCerts(endEntityCert);
		//setRequestorName(6, "URN:ValidationService:TEST:SCVPExample");
		//setRequestorText("LOG;HI;MAJ;OTH;APP,HTTP://FOO.GOV/,-");
		//setNonce(nonce);
		
		//Then, this method is called to produce the request.
		return null;
	}
}
