package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Certificate;

/*
 *    PKCReference ::= CHOICE {
     cert        [0] Certificate,
     pkcRef      [1] SCVPCertID }

 */
public class PKCReference extends ASN1Object {
	
	private Certificate cert = null;
	private SCVPCertID pkcRef = null;

	public PKCReference(Certificate cert) {
		this.cert = cert;
	}

	public PKCReference(SCVPCertID pkcRef) {
		this.pkcRef = pkcRef;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		if (cert != null) {
			return new DERTaggedObject(true, 0, cert);
		}
		if (pkcRef != null) {
			return new DERTaggedObject(true, 1, pkcRef);
		}
		return null;
	}

}
