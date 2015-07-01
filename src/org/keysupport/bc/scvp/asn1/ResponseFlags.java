package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/*
 *    ResponseFlags ::= SEQUENCE {
     fullRequestInResponse      [0] BOOLEAN DEFAULT FALSE,
     responseValidationPolByRef [1] BOOLEAN DEFAULT TRUE,
     protectResponse            [2] BOOLEAN DEFAULT TRUE,
     cachedResponse             [3] BOOLEAN DEFAULT TRUE }


 */
public class ResponseFlags extends ASN1Object {

	private ASN1Boolean fullRequestInResponse = null;
	private ASN1Boolean responseValidationPolByRef = null;
	private ASN1Boolean protectResponse = null;
	private ASN1Boolean cachedResponse = null;
	
	public ResponseFlags(boolean fullRequestInResponse, boolean responseValidationPolByRef, boolean protectResponse, boolean cachedResponse) {
		this.fullRequestInResponse = ASN1Boolean.getInstance(fullRequestInResponse);
		this.responseValidationPolByRef = ASN1Boolean.getInstance(responseValidationPolByRef);
		this.protectResponse = ASN1Boolean.getInstance(protectResponse);
		this.cachedResponse = ASN1Boolean.getInstance(cachedResponse);
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(new DERTaggedObject(true, 0, fullRequestInResponse));
		v.add(new DERTaggedObject(true, 1, responseValidationPolByRef));
		v.add(new DERTaggedObject(true, 2, protectResponse));
		v.add(new DERTaggedObject(true, 3, cachedResponse));
		return new DERSequence(v);
	}

}
