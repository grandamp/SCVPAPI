package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/*
 * ContentInfo ::= SEQUENCE {
        contentType ContentType,
        content [0] EXPLICIT ANY DEFINED BY contentType }

      ContentType ::= OBJECT IDENTIFIER
 */
public class SCVPRequest extends ASN1Object{

	public static final ASN1ObjectIdentifier idCtScvpCertValRequest = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.10");

	private ASN1ObjectIdentifier contentType = null;
	private CVRequest request = null;
	
	public SCVPRequest(ASN1ObjectIdentifier contentType, CVRequest request) {
		this.contentType = contentType;
		this.request = request;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(contentType);
		if (request != null) {
			v.add(new DERTaggedObject(true, 0, request));
		}
		return new DERSequence(v);
	}

}
