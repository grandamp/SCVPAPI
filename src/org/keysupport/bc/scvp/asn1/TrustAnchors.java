package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

public class TrustAnchors extends ASN1Object {

	private ASN1EncodableVector tas = new ASN1EncodableVector();

	public TrustAnchors(PKCReference[] taArray) {
		for (PKCReference ta : taArray) {
			tas.add(ta);
		}
	}

	public TrustAnchors() {
	}

	public void addTrustAnchor(PKCReference ta) {
		tas.add(ta);
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return new DERSequence(tas);
	}

}
