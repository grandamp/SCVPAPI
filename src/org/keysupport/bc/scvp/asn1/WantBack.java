package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class WantBack extends SeqOfASN1Object {

	/**
	 * id-swb-pkc-cert: The certificate that was the subject of the request;
	 */
	final static ASN1ObjectIdentifier idSwbPkcCert = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.10");
	/**
	 * id-swb-pkc-best-cert-path: The certification path built for the
	 * certificate including the certificate that was validated;
	 */
	final static ASN1ObjectIdentifier idSwbPkcBestCertPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.1");
	/**
	 * id-swb-pkc-revocation-info: Proof of revocation status for each
	 * certificate in the certification path;
	 */
	final static ASN1ObjectIdentifier idSwbPkcRevocationInfo = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.2");
	/**
	 * id-swb-pkc-public-key-info: The public key from the certificate that was
	 * the subject of the request;
	 */
	final static ASN1ObjectIdentifier idSwbPkcPublicKeyInfo = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.4");
	/**
	 * id-swb-pkc-all-cert-paths: A set of certification paths for the
	 * certificate that was the subject of the request;
	 */
	final static ASN1ObjectIdentifier idSwbPkcAllCertPaths = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.12");
	/**
	 * id-swb-pkc-ee-revocation-info: Proof of revocation status for the end
	 * entity certificate in the certification path; and
	 */
	final static ASN1ObjectIdentifier idSwbPkcEeRevocationInfo = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.13");
	/**
	 * id-swb-pkc-CAs-revocation-info: Proof of revocation status for each CA
	 * certificate in the certification path.
	 */
	final static ASN1ObjectIdentifier idSwbPkcCAsRevocationInfo = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.14");

	public WantBack(ASN1EncodableVector oids) {
		super(oids);
	}

}
