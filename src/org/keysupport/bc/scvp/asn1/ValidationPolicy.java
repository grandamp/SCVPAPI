package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/*
 *       ValidationPolicy ::= SEQUENCE {
 validationPolRef          ValidationPolRef,
 validationAlg         [0] ValidationAlg OPTIONAL,
 userPolicySet         [1] SEQUENCE SIZE (1..MAX) OF OBJECT
 IDENTIFIER OPTIONAL,
 inhibitPolicyMapping  [2] BOOLEAN OPTIONAL,
 requireExplicitPolicy [3] BOOLEAN OPTIONAL,
 inhibitAnyPolicy      [4] BOOLEAN OPTIONAL,
 trustAnchors          [5] TrustAnchors OPTIONAL,
 keyUsages             [6] SEQUENCE OF KeyUsage OPTIONAL,
 extendedKeyUsages     [7] SEQUENCE OF KeyPurposeId OPTIONAL,
 specifiedKeyUsages    [8] SEQUENCE OF KeyPurposeId OPTIONAL }

 */
public class ValidationPolicy extends ASN1Object {

	private ValidationPolRef validationPolRef = null;
	private ValidationAlg validationAlg = null;
	private UserPolicySet userPolicySet = null;
	private ASN1Boolean inhibitPolicyMapping = null;
	private ASN1Boolean requireExplicitPolicy = null;
	private ASN1Boolean inhibitAnyPolicy = null;
	private TrustAnchors trustAnchors = null;
	private KeyUsages keyUsages = null;
	private KeyPurposeIds extendedKeyUsages = null;
	private KeyPurposeIds specifiedKeyUsages = null;

	public ValidationPolicy(ValidationPolRef validationPolRef,
			ValidationAlg validationAlg, UserPolicySet userPolicySet,
			ASN1Boolean inhibitPolicyMapping,
			ASN1Boolean requireExplicitPolicy, ASN1Boolean inhibitAnyPolicy,
			TrustAnchors trustAnchors, KeyUsages keyUsages,
			KeyPurposeIds extendedKeyUsages, KeyPurposeIds specifiedKeyUsages) {
		this.validationPolRef = validationPolRef;
		this.validationAlg = validationAlg;
		this.userPolicySet = userPolicySet;
		this.inhibitPolicyMapping = inhibitPolicyMapping;
		this.requireExplicitPolicy = requireExplicitPolicy;
		this.inhibitAnyPolicy = inhibitAnyPolicy;
		this.trustAnchors = trustAnchors;
		this.keyUsages = keyUsages;
		this.extendedKeyUsages = extendedKeyUsages;
		this.specifiedKeyUsages = specifiedKeyUsages;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(validationPolRef);
		if (validationAlg != null) {
			v.add(new DERTaggedObject(true, 0, validationAlg));
		}
		if (userPolicySet != null) {
			v.add(new DERTaggedObject(true, 1, userPolicySet));
		}
		if (inhibitPolicyMapping != null) {
			v.add(new DERTaggedObject(true, 2, inhibitPolicyMapping));
		}
		if (requireExplicitPolicy != null) {
			v.add(new DERTaggedObject(true, 3, requireExplicitPolicy));
		}
		if (inhibitAnyPolicy != null) {
			v.add(new DERTaggedObject(true, 4, inhibitAnyPolicy));
		}
		if (trustAnchors != null) {
			v.add(new DERTaggedObject(true, 5, trustAnchors));
		}
		if (keyUsages != null) {
			v.add(new DERTaggedObject(true, 6, keyUsages));
		}
		if (extendedKeyUsages != null) {
			v.add(new DERTaggedObject(true, 7, extendedKeyUsages));
		}
		if (specifiedKeyUsages != null) {
			v.add(new DERTaggedObject(true, 7, specifiedKeyUsages));
		}
		return new DERSequence(v);
	}

}
