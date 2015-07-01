package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Certificate;

/*
 *    PKCReference ::= CHOICE {
     cert        [0] Certificate,
     pkcRef      [1] SCVPCertID }

 */
public class PKCReference extends ASN1Object implements ASN1Choice {
	
	/*
	 * To minimize the headache, we are only
	 * gonna support Certificate based
	 * PKCReferences for now.
	 */
	private DERTaggedObject ref = null;

	public PKCReference(Certificate cert) {
		this.ref = new DERTaggedObject(false, 0, cert);
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return new DERTaggedObject(false, 0, ref);
	}

}
