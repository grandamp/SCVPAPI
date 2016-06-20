package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

/*
 *       ValPolRequest ::= SEQUENCE {
        vpRequestVersion           INTEGER DEFAULT 1,
        requestNonce               OCTET STRING }

 */
public class ValPolRequest extends ASN1Object{

	private final ASN1Integer vpRequestVersion = new ASN1Integer(1);
	private ASN1OctetString requestNonce = null;
	
	public ValPolRequest(ASN1OctetString requestNonce) {
		this.requestNonce = requestNonce;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(vpRequestVersion);
		v.add(requestNonce);
		return new DERSequence(v);
	}

}
