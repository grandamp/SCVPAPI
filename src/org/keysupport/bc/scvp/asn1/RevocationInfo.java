package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.CertificateList;

/*
 *       RevocationInfo ::= CHOICE {
        crl                    [0] CertificateList,
        delta-crl              [1] CertificateList,
        ocsp                   [2] OCSPResponse,
        other                  [3] OtherRevInfo }

 */
public class RevocationInfo extends ASN1Object {

	private CertificateList crl = null;
	private CertificateList deltaCrl = null;
	private OCSPResponse ocsp = null;
	private OtherRevInfo other = null;

	public RevocationInfo() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		if (crl != null) {
			v.add(new DERTaggedObject(false, 0, crl));
		}
		if (deltaCrl != null) {
			v.add(new DERTaggedObject(false, 1, deltaCrl));
		}
		if (ocsp != null) {
			v.add(new DERTaggedObject(false, 2, ocsp));
		}
		if (other != null) {
			v.add(new DERTaggedObject(false, 3, other));
		}
		return new DERSequence(v); 
	}

}
