package org.keysupport.fpki;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * See:
 * http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-2.pdf#page=123
 * 
 * This class provides a List<String> or List<ASN1ObjectIdentifier> for each LOA
 * defined in the document above.
 * 
 * @author Todd E. Johnson
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
	 * (2) "The Federal PKI has also added two policies, Medium Commercial Best Practices
	 * (Medium-CBP) and Medium Hardware Commercial Best Practices (MediumHW-CBP)
	 * to support recognition of non-Federal PKIs. In terms of e-authentication levels, the
	 * Medium CBP and MediumHW-CBP are equivalent to Medium and Medium-HW, respectively."
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
	 * <pre>
	 * LOA 3 Policy Identifiers:
	 * 
	 * 2.16.840.1.101.3.2.1.3.6 - Common-SW
	 * 2.16.840.1.101.3.2.1.3.2 - FBCA Basic
	 * 2.16.840.1.101.3.2.1.3.3 - FBCA Medium
	 * 2.16.840.1.101.3.2.1.3.41 - id-common-derived-pivAuth (1)
	 * 2.16.840.1.101.3.2.1.3.14 - Medium-CBP (2)
	 * </pre>
	 * 
	 * (1) While id-common-derived-pivAuth is not listed in NIST SP
	 * 800-63-2, it is intended to be an LOA4 credential, where the OID
	 * assignment occurred after the publication of 800-63-2.
	 * 
	 * (2) "The Federal PKI has also added two policies, Medium Commercial Best Practices
	 * (Medium-CBP) and Medium Hardware Commercial Best Practices (MediumHW-CBP)
	 * to support recognition of non-Federal PKIs. In terms of e-authentication levels, the
	 * Medium CBP and MediumHW-CBP are equivalent to Medium and Medium-HW, respectively."
	 */
	public static final List<ASN1ObjectIdentifier> LOA3;
	static {
		List<ASN1ObjectIdentifier> loaThree = new ArrayList<ASN1ObjectIdentifier>();
		loaThree.add(FPKIPolicyObjectIdentifiers.id_fpki_common_policy);
		loaThree.add(FPKIPolicyObjectIdentifiers.id_fpki_certpcy_basicassurance);
		loaThree.add(FPKIPolicyObjectIdentifiers.id_fpki_certpcy_mediumassurance);
		loaThree.add(FPKIPolicyObjectIdentifiers.id_fpki_common_derived_pivauth_hardware);
		loaThree.add(FPKIPolicyObjectIdentifiers.id_fpki_certpcy_medium_cbp);
		LOA3 = Collections.unmodifiableList(loaThree);
	}

	/**
	 * <pre>
	 * LOA 2 Policy Identifiers:
	 * 
	 * 2.16.840.1.101.3.2.1.3.17 - Common-cardAuth
	 * 2.16.840.1.101.3.2.1.3.19 - PIVI-cardAuth
	 * 2.16.840.1.101.3.2.1.3.27 - SHA1-cardAuth
	 * </pre>
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
	 * Method getStringList.
	 * 
	 * This method converts a List<ASN1ObjectIdentifier> to 
	 * List<String>.
	 * 
	 * @param loa List<ASN1ObjectIdentifier>
	 * @return List<String>
	 */
	public static List<String> getStringList(List<ASN1ObjectIdentifier> loa) {
		List<String> strLoa = new ArrayList<String>();
		for (ASN1ObjectIdentifier oid : loa) {
			strLoa.add(oid.getId());
		}
		return strLoa;
	}
}
