package org.keysupport.fpki;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * See:
 * http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-2.pdf
 * #page=123
 * 
 * This class provides a List<String> or List<ASN1ObjectIdentifier> for each LOA
 * defined in the document above.
 * 
 * @author Todd E. Johnson
 * @version $Revision: 1.0 $
 */
public class NISTeAuthPkiLoa {

	/**
	 * <pre>
	 * LOA 4 Policy Identifiers:
	 * 
	 * 2.16.840.1.101.3.2.1.3.13 - Common-Auth
	 * 2.16.840.1.101.3.2.1.3.18 - PIVI-Auth/PIVI-HW
	 * 2.16.840.1.101.3.2.1.3.26 - SHA1-Auth
	 * 2.16.840.1.101.3.2.1.3.7 - Common-HW
	 * 2.16.840.1.101.3.2.1.3.24 - SHA1-HW
	 * 2.16.840.1.101.3.2.1.3.16 - Common-High
	 * 2.16.840.1.101.3.2.1.3.12 - FBCA Medium-HW
	 * 2.16.840.1.101.3.2.1.3.4  - FBCA High
	 * 2.16.840.1.101.3.2.1.3.41 - id-common-derived-pivAuth-hardware (1)
	 * 2.16.840.1.101.3.2.1.3.15 - MediumHW-CBP (2)
	 * </pre>
	 * 
	 * (1) While id-common-derived-pivAuth-hardware is not listed in NIST SP
	 * 800-63-2, it is intended to be an LOA4 credential, where the OID
	 * assignment occurred after the publication of 800-63-2.
	 * 
	 * (2) "The Federal PKI has also added two policies, Medium Commercial Best
	 * Practices (Medium-CBP) and Medium Hardware Commercial Best Practices
	 * (MediumHW-CBP) to support recognition of non-Federal PKIs. In terms of
	 * e-authentication levels, the Medium CBP and MediumHW-CBP are equivalent
	 * to Medium and Medium-HW, respectively."
	 */
	public static final List<ASN1ObjectIdentifier> LOA4;
	static {
		List<ASN1ObjectIdentifier> loaFour = new ArrayList<ASN1ObjectIdentifier>();
		loaFour.add(FPKIPolicyObjectIdentifiers.id_fpki_common_authentication);
		loaFour.add(FPKIPolicyObjectIdentifiers.id_fpki_certpcy_pivi_hardware);
		loaFour.add(FPKIPolicyObjectIdentifiers.id_fpki_sha1_authentication);
		loaFour.add(FPKIPolicyObjectIdentifiers.id_fpki_common_hardware);
		loaFour.add(FPKIPolicyObjectIdentifiers.id_fpki_sha1_hardware);
		loaFour.add(FPKIPolicyObjectIdentifiers.id_fpki_common_high);
		loaFour.add(FPKIPolicyObjectIdentifiers.id_fpki_certpcy_mediumhardware);
		loaFour.add(FPKIPolicyObjectIdentifiers.id_fpki_certpcy_highassurance);
		loaFour.add(FPKIPolicyObjectIdentifiers.id_fpki_common_derived_pivauth_hardware);
		loaFour.add(FPKIPolicyObjectIdentifiers.id_fpki_certpcy_mediumhw_cbp);
		LOA4 = Collections.unmodifiableList(loaFour);
	}

	/**
	 * Field LOA4_INHIBIT_ANY_POLICY.
	 * (value is true)
	 */
	public static final boolean LOA4_INHIBIT_ANY_POLICY = true;

	/**
	 * Field LOA4_REQUIRE_EXPLICIT_POLICY.
	 * (value is true)
	 */
	public static final boolean LOA4_REQUIRE_EXPLICIT_POLICY = true;

	/**
	 * Field LOA4_INHIBIT_POLICY_MAPPING.
	 * (value is false)
	 */
	public static final boolean LOA4_INHIBIT_POLICY_MAPPING = false;

	/**
	 * <pre>
	 * LOA 3 Policy Identifiers:
	 * 
	 * 2.16.840.1.101.3.2.1.3.6 - Common-SW
	 * 2.16.840.1.101.3.2.1.3.2 - FBCA Basic
	 * 2.16.840.1.101.3.2.1.3.3 - FBCA Medium
	 * 2.16.840.1.101.3.2.1.3.41 - id-common-derived-pivAuth (1)
	 * 2.16.840.1.101.3.2.1.3.14 - Medium-CBP (2)
	 * [all LOA4 is appended to this list]
	 * </pre>
	 * 
	 * (1) While id-common-derived-pivAuth is not listed in NIST SP 800-63-2, it
	 * is intended to be an LOA4 credential, where the OID assignment occurred
	 * after the publication of 800-63-2.
	 * 
	 * (2) "The Federal PKI has also added two policies, Medium Commercial Best
	 * Practices (Medium-CBP) and Medium Hardware Commercial Best Practices
	 * (MediumHW-CBP) to support recognition of non-Federal PKIs. In terms of
	 * e-authentication levels, the Medium CBP and MediumHW-CBP are equivalent
	 * to Medium and Medium-HW, respectively."
	 */
	public static final List<ASN1ObjectIdentifier> LOA3;
	static {
		List<ASN1ObjectIdentifier> loaThree = new ArrayList<ASN1ObjectIdentifier>();
		loaThree.add(FPKIPolicyObjectIdentifiers.id_fpki_common_policy);
		loaThree.add(FPKIPolicyObjectIdentifiers.id_fpki_certpcy_basicassurance);
		loaThree.add(FPKIPolicyObjectIdentifiers.id_fpki_certpcy_mediumassurance);
		loaThree.add(FPKIPolicyObjectIdentifiers.id_fpki_common_derived_pivauth_hardware);
		loaThree.add(FPKIPolicyObjectIdentifiers.id_fpki_certpcy_medium_cbp);
		loaThree.addAll(LOA4);
		LOA3 = Collections.unmodifiableList(loaThree);
	}

	/**
	 * Field LOA3_INHIBIT_ANY_POLICY.
	 * (value is true)
	 */
	public static final boolean LOA3_INHIBIT_ANY_POLICY = true;

	/**
	 * Field LOA3_REQUIRE_EXPLICIT_POLICY.
	 * (value is true)
	 */
	public static final boolean LOA3_REQUIRE_EXPLICIT_POLICY = true;

	/**
	 * Field LOA3_INHIBIT_POLICY_MAPPING.
	 * (value is false)
	 */
	public static final boolean LOA3_INHIBIT_POLICY_MAPPING = false;

	/**
	 * <pre>
	 * LOA 2 Policy Identifiers:
	 * 
	 * 2.16.840.1.101.3.2.1.3.17 - Common-cardAuth
	 * 2.16.840.1.101.3.2.1.3.19 - PIVI-cardAuth
	 * 2.16.840.1.101.3.2.1.3.27 - SHA1-cardAuth
	 * </pre>
	 * 
	 * [note] This LOA is less actionable, because it specifies policy
	 * identifiers for card authentication certificates. I.e., the certificates
	 * are not issued to a human subscriber, but to a card. The associated
	 * private key to these certificates may be used without activation data.
	 * I.e., can be used without a pin!
	 * 
	 * Further, 800-63-2 does not provide a specific set of OIDs beyond the card
	 * authentication certificates, but states:
	 * 
	 * "At Level 2 agencies may use certificates issued under policies that have
	 * not been mapped by the Federal policy authority, but are determined to
	 * meet the Level 2 identify proofing, token and status reporting
	 * requirements. (For this evaluation, a strict compliance mapping should be
	 * used, rather than the rough mapping used for the FPKI policies.)"
	 * 
	 * This implementation can not provide an actionable set of OIDs because the
	 * author is unwilling to perform such policy/compliance mapping ;)
	 */
	public static final List<ASN1ObjectIdentifier> LOA2;
	static {
		List<ASN1ObjectIdentifier> loaTwo = new ArrayList<ASN1ObjectIdentifier>();
		loaTwo.add(FPKIPolicyObjectIdentifiers.id_fpki_common_cardauth);
		loaTwo.add(FPKIPolicyObjectIdentifiers.id_fpki_certpcy_pivi_cardauth);
		loaTwo.add(FPKIPolicyObjectIdentifiers.id_fpki_sha1_cardauth);
		LOA2 = Collections.unmodifiableList(loaTwo);
	}

	/**
	 * Method getTrustAnchor.
	 * @return X509Certificate
	 * @throws CertificateException
	 */
	public static final X509Certificate getTrustAnchor()
			throws CertificateException {
		return CommonPolicyRootCA.getInstance().getCertificate();
	}

	/**
	 * Method getStringList.
	 * 
	 * This method converts a List<ASN1ObjectIdentifier> to List<String>.
	 * 
	 * @param loa
	 *            List<ASN1ObjectIdentifier>
	
	 * @return List<String> */
	public static List<String> getStringList(List<ASN1ObjectIdentifier> loa) {
		List<String> strLoa = new ArrayList<String>();
		for (ASN1ObjectIdentifier oid : loa) {
			strLoa.add(oid.getId());
		}
		return strLoa;
	}

}
