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
import org.keysupport.bc.scvp.asn1.ResponseFlags;
import org.keysupport.bc.scvp.asn1.SCVPRequest;
import org.keysupport.bc.scvp.asn1.TrustAnchors;
import org.keysupport.bc.scvp.asn1.UserPolicySet;
import org.keysupport.bc.scvp.asn1.ValidationPolRef;
import org.keysupport.bc.scvp.asn1.ValidationPolicy;
import org.keysupport.bc.scvp.asn1.WantBack;

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
	private WantBack wantBack = null;
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

	public void setCertReference(Certificate cert) {
		this.queriedCerts = new CertReferences(new PKCReference(cert));
	}

	public void addCertReference(Certificate cert) {
		this.queriedCerts = new CertReferences(new PKCReference(cert));
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
//		validationPolicy = new ValidationPolicy(validationPolRef, null, initialPolicies,
//				null, null, null, null, null, null, null);
		/*
		 * Now we are going to create our ResponseFlags to inject into the Query
		 */
		boolean fullRequestInResponse = true;
		boolean responseValidationPolByRef = false;
		boolean protectResponse = true;
		boolean cachedResponse = false;
		ResponseFlags responseFlags = new ResponseFlags(fullRequestInResponse, responseValidationPolByRef, protectResponse, cachedResponse);
		/*
		 * Next, we build the Query with the settings called, adding the ValidationPolicy.
		 */
		query = new Query(queriedCerts, checks, wantBack, validationPolicy, responseFlags, null, null, null,
				null, null, null);
		/*
		 * Specify 1.2.840.113549.1.1.11 - sha256WithRSAEncryption for response signing
		 */
		//AlgorithmIdentifier sha256WithRSAEncryption = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.11"));
		/*
		 * Now we construct the CVRequest, and add the Query.
		 */
		request = new CVRequest(query, null, requestNonce, requestorName, null, null, null, null, requestorText);
		/*
		 * Finally, we envelope the CVRequest in a CMS message and return to the caller.
		 */
		encapRequest = new SCVPRequest(request);
		return encapRequest;
	}

	public SCVPRequest getEncapRequest() {
		return encapRequest;
	}
	
	public CVRequest getRequest() {
		return request;
	}
	
	public Query getQuery() {
		return query;
	}
	
	public ValidationPolicy getValidationPolicy() {
		return validationPolicy;
	}

	/**
	 * @return the wantBack
	 */
	public WantBack getWantBack() {
		return wantBack;
	}

	/**
	 * @param wantBack the wantBack to set
	 */
	public void setWantBack(WantBack wantBack) {
		this.wantBack = wantBack;
	}

}
