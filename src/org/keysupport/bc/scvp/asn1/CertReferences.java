package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;

/*
 *    CertReferences ::= CHOICE {
 pkcRefs     [0] SEQUENCE SIZE (1..MAX) OF PKCReference,
 acRefs      [1] SEQUENCE SIZE (1..MAX) OF ACReference }

 */

/*
 * TODO:  This class will require more work using an abstract reference
 */
public class CertReferences extends ASN1Object implements ASN1Choice {
	
	/*
	 * To minimize the headache, we are only
	 * gonna support Certificate based
	 * PKCReferences for now.
	 */
	public static final int pkcRefs = 0;
	public static final int acRefs = 1;
	
	PKCReference ref = null;

	public CertReferences(PKCReference ref) {
		this.ref = ref;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return new DERTaggedObject(false, pkcRefs, ref);
	}

}
