package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

/*
 * 
      ValidationAlg ::= SEQUENCE {
        valAlgId              OBJECT IDENTIFIER,
        parameters            ANY DEFINED BY valAlgId OPTIONAL }

 */
public class ValidationAlg extends ASN1Object {

	private ASN1ObjectIdentifier valAlgId = null;
	private ASN1Object parameters = null;

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(valAlgId);
		v.add(parameters);
		return new DERSequence(v);
	}

}
