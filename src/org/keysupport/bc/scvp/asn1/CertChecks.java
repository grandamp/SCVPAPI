package org.keysupport.bc.scvp.asn1;

import java.util.Vector;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class CertChecks extends SeqOfASN1Object {

	final static ASN1ObjectIdentifier idStcBuildPkcPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.1");
	final static ASN1ObjectIdentifier idStcBuildValidPkcPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.2");
	final static ASN1ObjectIdentifier idStcBuildStatusCheckedPkcPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.3");
	final static ASN1ObjectIdentifier idStcBuildAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.4");
	final static ASN1ObjectIdentifier idStcBuildValidAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.5");
	final static ASN1ObjectIdentifier idStcBuildStatusCheckedAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.6");
	final static ASN1ObjectIdentifier idStcStatusCheckAcAndBuildStatusCheckedAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.7");

	public CertChecks(Vector<ASN1Object> oids) {
		super(oids);
	}

	public CertChecks() {
		super();
	}

}
