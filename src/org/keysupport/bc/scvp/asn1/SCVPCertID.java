package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.IssuerSerial;

/*
 *  SCVPCertID ::= SEQUENCE {
       certHash        OCTET STRING,
       issuerSerial    SCVPIssuerSerial,
       hashAlgorithm   AlgorithmIdentifier DEFAULT { algorithm sha-1 } }

 */
public class SCVPCertID extends ASN1Object {
	
	private ASN1OctetString certHash = null;
	private IssuerSerial issuerSerial = null;
	private AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));

	public SCVPCertID() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(certHash);
		v.add(issuerSerial);
		v.add(hashAlgorithm);
		return new DERSequence(v);
	}

}
