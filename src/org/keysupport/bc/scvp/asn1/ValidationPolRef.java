package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

/*
 *       ValidationPolRef::= SEQUENCE {
        valPolId              OBJECT IDENTIFIER,
        valPolParams          ANY DEFINED BY valPolId OPTIONAL }

 */
public class ValidationPolRef extends ASN1Object {

	private ASN1ObjectIdentifier valPolId = null;
	private ASN1Object valPolParams = null;

	public ValidationPolRef(ASN1ObjectIdentifier valPolId, ASN1Object valPolParams) {
		this.valPolId = valPolId;
		this.valPolParams = valPolParams;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(valPolId);
		if (valPolParams != null) {
			v.add(valPolParams);
		}
		return new DERSequence(v);
	}

}
