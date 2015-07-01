package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class CertChecks extends SeqOfASN1Object {

	public final static ASN1ObjectIdentifier idStcBuildPkcPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.1");
	public final static ASN1ObjectIdentifier idStcBuildValidPkcPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.2");
	public final static ASN1ObjectIdentifier idStcBuildStatusCheckedPkcPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.3");
	public final static ASN1ObjectIdentifier idStcBuildAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.4");
	public final static ASN1ObjectIdentifier idStcBuildValidAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.5");
	public final static ASN1ObjectIdentifier idStcBuildStatusCheckedAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.6");
	public final static ASN1ObjectIdentifier idStcStatusCheckAcAndBuildStatusCheckedAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.7");

	public CertChecks(ASN1EncodableVector oids) {
		super(oids);
	}

	public CertChecks() {
		super();
	}

}
