package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/*
 *    ValPolResponse ::= SEQUENCE {
 *      vpResponseVersion               INTEGER,
 *      maxCVRequestVersion             INTEGER,
 *      maxVPRequestVersion             INTEGER,
 *      serverConfigurationID           INTEGER,
 *      thisUpdate                      GeneralizedTime,
 *      nextUpdate                      GeneralizedTime OPTIONAL,
 *      supportedChecks                 CertChecks,
 *      supportedWantBacks              WantBack,
 *      validationPolicies              SEQUENCE OF OBJECT IDENTIFIER,
 *      validationAlgs                  SEQUENCE OF OBJECT IDENTIFIER,
 *      authPolicies                    SEQUENCE OF AuthPolicy,
 *      responseTypes                   ResponseTypes,
 *      defaultPolicyValues             RespValidationPolicy,
 *      revocationInfoTypes             RevocationInfoTypes,
 *      signatureGeneration             SEQUENCE OF AlgorithmIdentifier,
 *      signatureVerification           SEQUENCE OF AlgorithmIdentifier,
 *      hashAlgorithms                  SEQUENCE SIZE (1..MAX) OF
 *                                         OBJECT IDENTIFIER,
 *      serverPublicKeys                SEQUENCE OF KeyAgreePublicKey
 *                                         OPTIONAL,
 *      clockSkew                       INTEGER DEFAULT 10,
 *      requestNonce                    OCTET STRING OPTIONAL }
 *  
 */
public class ValPolResponse extends ASN1Object {

	private ASN1Sequence seq = null;
	private ASN1Integer vpResponseVersion = null;
	private ASN1Integer maxCVRequestVersion = null;
	private ASN1Integer maxVPRequestVersion = null;
	private ASN1Integer serverConfigurationID = null;
	private ASN1GeneralizedTime thisUpdate = null;
	private ASN1GeneralizedTime nextUpdate = null;
	private CertChecks supportedChecks = null;
	private WantBack supportedWantBacks = null;
	private SeqOfASN1Object validationPolicies = null;
	private SeqOfASN1Object validationAlgs = null;
	private SeqOfASN1Object authPolicies = null;
	private ResponseTypes responseTypes = null;
	private ValidationPolicy defaultPolicyValues = null;
	private RevocationInfoTypes revocationInfoTypes = null;
	private SeqOfASN1Object signatureGeneration = null;
	private SeqOfASN1Object signatureVerification = null;
	private SeqOfASN1Object hashAlgorithms = null;
	private SeqOfASN1Object serverPublicKeys = null;
	private ASN1Integer clockSkew = null;
	private ASN1OctetString requestNonce = null;
	
	private ValPolResponse(ASN1Sequence seq) {
		this.seq = seq;
	}

	

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		//v.add(...);
		return new DERSequence(v);
	}

}
