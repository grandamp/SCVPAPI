package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AttributeCertificate;

/*
 *    ACReference ::= CHOICE {
     attrCert    [2] AttributeCertificate,
     acRef       [3] SCVPCertID }

 */
public class ACReference extends ASN1Object {

	private AttributeCertificate attrCert = null;
	private SCVPCertID acRef = null;

	public ACReference(AttributeCertificate attrCert, SCVPCertID acRef) {
		this.attrCert = attrCert;
		this.acRef = acRef;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		if (attrCert != null) {
			return new DERTaggedObject(true, 2, attrCert);
		}
		if (acRef != null) {
			return new DERTaggedObject(true, 3, acRef);
		}
		return null;
	}

}
