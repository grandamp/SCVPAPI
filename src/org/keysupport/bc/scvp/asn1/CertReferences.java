package org.keysupport.bc.scvp.asn1;

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
public class CertReferences extends ASN1Object {
	
	public static final int pkcRefs = 0;
	public static final int acRefs = 1;
	
	private int refType = -1;
	private SeqOfASN1Object refs = null;

	

	public CertReferences(SeqOfASN1Object refs, int refType) {
		this.refs = refs;
		this.refType = refType;
	}

	public CertReferences() {
	}

	public void addReference(ASN1Object ref, int refType) {
		this.refs.addObj(ref);
		this.refType = refType;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return new DERTaggedObject(true, refType, refs);
	}

}
