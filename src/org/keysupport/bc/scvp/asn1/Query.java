package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extensions;

/*
 *  Query ::= SEQUENCE {
 queriedCerts            CertReferences,
 checks                  CertChecks,
 -- Note: tag [0] not used --
 wantBack            [1] WantBack OPTIONAL,
 validationPolicy        ValidationPolicy,
 responseFlags           ResponseFlags OPTIONAL,
 serverContextInfo   [2] OCTET STRING OPTIONAL,
 validationTime      [3] GeneralizedTime OPTIONAL,
 intermediateCerts   [4] CertBundle OPTIONAL,
 revInfos            [5] RevocationInfos OPTIONAL,
 producedAt          [6] GeneralizedTime OPTIONAL,
 queryExtensions     [7] Extensions OPTIONAL }

 */
public class Query extends ASN1Object {

	private CertReferences queriedCerts = null;
	private CertChecks checks = null;
	private WantBack wantBack = null;
	private ValidationPolicy validationPolicy = null;
	private ResponseFlags responseFlags = null;
	private ASN1OctetString serverContextInfo = null;
	private ASN1GeneralizedTime validationTime = null;
	private CertBundle intermediateCerts = null;
	private RevocationInfos revInfos = null;
	private ASN1GeneralizedTime producedAt = null;
	private Extensions queryExtensions = null;

	public Query(CertReferences queriedCerts, CertChecks checks,
			WantBack wantBack, ValidationPolicy validationPolicy,
			ResponseFlags responseFlags, ASN1OctetString serverContextInfo,
			ASN1GeneralizedTime validationTime, CertBundle intermediateCerts,
			RevocationInfos revInfos, ASN1GeneralizedTime producedAt,
			Extensions queryExtensions) {
		this.queriedCerts = queriedCerts;
		this.checks = checks;
		this.wantBack = wantBack;
		this.validationPolicy = validationPolicy;
		this.responseFlags = responseFlags;
		this.serverContextInfo = serverContextInfo;
		this.validationTime = validationTime;
		this.intermediateCerts = intermediateCerts;
		this.revInfos = revInfos;
		this.producedAt = producedAt;
		this.queryExtensions = queryExtensions;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(queriedCerts);
		v.add(checks);
		if (wantBack != null) {
			v.add(new DERTaggedObject(true, 1, wantBack));
		}
		v.add(validationPolicy);
		if (responseFlags != null) {
			v.add(responseFlags);
		}
		if (serverContextInfo != null) {
			v.add(new DERTaggedObject(true, 2, serverContextInfo));
		}
		if (validationTime != null) {
			v.add(new DERTaggedObject(true, 3, validationTime));
		}
		if (intermediateCerts != null) {
			v.add(new DERTaggedObject(true, 4, intermediateCerts));
		}
		if (revInfos != null) {
			v.add(new DERTaggedObject(true, 5, revInfos));
		}
		if (producedAt != null) {
			v.add(new DERTaggedObject(true, 6, producedAt));
		}
		if (queryExtensions != null) {
			v.add(new DERTaggedObject(true, 7, queryExtensions));
		}
		return new DERSequence(v);
	}

}
