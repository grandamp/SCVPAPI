package org.keysupport.fpki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/*
 * This interface is intended to provide a java
 * representation of the NIST Computer Security
 * Object Registry (CSOR) for the Federal PKI
 * policies: 
 * 
 * http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/pki_registration.html
 */
public interface FPKIPolicyObjectIdentifiers {

	/*
	 * csor-pki ::= {joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) pki(2)}
	 */
	public static final ASN1ObjectIdentifier csor_pki = new ASN1ObjectIdentifier("2.16.840.1.101.3.2");
	

	/*
	 * Policies OIDs are allocated in the following arc:
	 * 
	 * 	csor-certpolicy ::= { csor-pki 1 }
	 */
	public static final ASN1ObjectIdentifier csor_certpolicy = csor_pki.branch("1");

	/*
	 * ACES Registered Objects 
	 * There are eight objects registered to support the ACES project. The first object is an arc for ACES policies. These objects define an arc for policies associated with the GSA ACES project.
	 * 
	 * 	-- the ACES policy arc
	 * 	aces OBJECT IDENTIFIER ::= { csor-certpolicy 1 }
	 */
	public static final ASN1ObjectIdentifier aces = csor_certpolicy.branch("1");
	
	/*
	 * -- the aces policy OIDs
	 * The seven policies below are defined in "Revised Certificate Policy for Access Certificates for Electronic Services".
	 */
	public static final ASN1ObjectIdentifier aces_ca = aces.branch("1");
	public static final ASN1ObjectIdentifier aces_identity = aces.branch("2");
	public static final ASN1ObjectIdentifier aces_business_rep = aces.branch("3");
	public static final ASN1ObjectIdentifier aces_relying_party = aces.branch("4");
	public static final ASN1ObjectIdentifier aces_ssl = aces.branch("5");
	public static final ASN1ObjectIdentifier aces_fed_employee = aces.branch("6");
	public static final ASN1ObjectIdentifier aces_fed_employee_hw = aces.branch("7");

	/*
	 * U.S. Patent And Trademark Office Registered Objects
	 * There are eleven policies registered with the U.S. Patent and Trademark Office. The first object is an arc for PTO policies. These OIDs have been assigned to this agency; however, we do not have the agency Certificate Profile associated with these OIDs.
	 * 
	 * -- the PTO policy arc
	 * pto-policies OBJECT IDENTIFIER ::= { csor-certpolicy 2 }
	 */
	public static final ASN1ObjectIdentifier pto_policies = csor_certpolicy.branch("2");

	/*
	 * -- the pto policy OIDs
	 */
	public static final ASN1ObjectIdentifier pto_registered_practitioner = pto_policies.branch("1");
	public static final ASN1ObjectIdentifier pto_inventor = pto_policies.branch("2");
	public static final ASN1ObjectIdentifier pto_practitioner_employee = pto_policies.branch("3");
	public static final ASN1ObjectIdentifier pto_basic = pto_policies.branch("4");
	public static final ASN1ObjectIdentifier pto_service_provider = pto_policies.branch("5");
	public static final ASN1ObjectIdentifier pto_service_provider_registrar = pto_policies.branch("6");

	/*
	 * The following policies are defined in the document: "Certificate Policy for the U.S. Patent and Trademark Office".
	 */
	public static final ASN1ObjectIdentifier pto_basic_2003 = pto_policies.branch("7");
	public static final ASN1ObjectIdentifier pto_medium_2003 = pto_policies.branch("8");
	public static final ASN1ObjectIdentifier id_pto_mediumhardware = pto_policies.branch("9");
	public static final ASN1ObjectIdentifier id_pto_cardauth = pto_policies.branch("10");

	/*
	 * Federal Bridge Certification Authority Registered Objects
	 * Forty objects have been registered to support the Federal Bridge Certification Authority. The first object is an arc for FBCA policies;
	 *
	 * -- the FBCA policy arc
	 * fbca-policies OBJECT IDENTIFIER ::= { csor-certpolicy 3 }
	 */
	public static final ASN1ObjectIdentifier fbca_policies = csor_certpolicy.branch("3");
	
	/*
	 * -- the fbca policy OIDs
	 * 
	 * The polices below are defined by the FBCA certificate policy.
	 */
	public static final ASN1ObjectIdentifier id_fpki_certpcy_rudimentaryassurance = fbca_policies.branch("1");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_basicassurance = fbca_policies.branch("2");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_mediumassurance = fbca_policies.branch("3");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_highassurance = fbca_policies.branch("4");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_testassurance = fbca_policies.branch("5");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_mediumhardware = fbca_policies.branch("12");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_medium_cbp = fbca_policies.branch("14");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_mediumhw_cbp = fbca_policies.branch("15");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_pivi_hardware = fbca_policies.branch("18");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_pivi_cardauth = fbca_policies.branch("19");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_pivi_contentsigning = fbca_policies.branch("20");
	public static final ASN1ObjectIdentifier id_fpki_sha1_medium_cbp = fbca_policies.branch("21");
	public static final ASN1ObjectIdentifier id_fpki_sha1_mediumhw_cbp = fbca_policies.branch("22");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_mediumdevice = fbca_policies.branch("37");
	public static final ASN1ObjectIdentifier id_fpki_certpcy_mediumdevicehardware = fbca_policies.branch("38");
	
	/*
	 * The policies below are defined in "X.509 Certificate Policy for the Common Policy Framework".
	 */
	public static final ASN1ObjectIdentifier id_fpki_common_policy = fbca_policies.branch("6");
	public static final ASN1ObjectIdentifier id_fpki_common_hardware = fbca_policies.branch("7");
	public static final ASN1ObjectIdentifier id_fpki_common_devices = fbca_policies.branch("8");
	public static final ASN1ObjectIdentifier id_fpki_common_authentication = fbca_policies.branch("13");
	public static final ASN1ObjectIdentifier id_fpki_common_high = fbca_policies.branch("16");
	public static final ASN1ObjectIdentifier id_fpki_common_cardauth = fbca_policies.branch("17");
	public static final ASN1ObjectIdentifier id_fpki_sha1_policy = fbca_policies.branch("23");
	public static final ASN1ObjectIdentifier id_fpki_sha1_hardware = fbca_policies.branch("24");
	public static final ASN1ObjectIdentifier id_fpki_sha1_devices = fbca_policies.branch("25");
	public static final ASN1ObjectIdentifier id_fpki_sha1_authentication = fbca_policies.branch("26");
	public static final ASN1ObjectIdentifier id_fpki_sha1_cardauth = fbca_policies.branch("27");
	public static final ASN1ObjectIdentifier id_fpki_common_deviceshardware = fbca_policies.branch("36");
	public static final ASN1ObjectIdentifier id_fpki_common_piv_contentsigning = fbca_policies.branch("39");
	public static final ASN1ObjectIdentifier id_fpki_common_derived_pivauth = fbca_policies.branch("40");
	public static final ASN1ObjectIdentifier id_fpki_common_derived_pivauth_hardware = fbca_policies.branch("41");

	/*
	 * The policies below are defined in X.509 Certificate Policy for the E-Governance Certification Authority. Once approved, this document will be available at the "Federal Public Key Infrastructure (FPKI) Policy Authority" website
	 */
	public static final ASN1ObjectIdentifier id_egov_level1 = fbca_policies.branch("9");
	public static final ASN1ObjectIdentifier id_egov_level2 = fbca_policies.branch("10");
	public static final ASN1ObjectIdentifier id_egov_applications = fbca_policies.branch("11");
	public static final ASN1ObjectIdentifier id_egov_level1_idp = fbca_policies.branch("28");
	public static final ASN1ObjectIdentifier id_egov_level2_idp = fbca_policies.branch("29");
	public static final ASN1ObjectIdentifier id_egov_level3_idp = fbca_policies.branch("30");
	public static final ASN1ObjectIdentifier id_egov_level4_idp = fbca_policies.branch("31");
	public static final ASN1ObjectIdentifier id_egov_bae_broker = fbca_policies.branch("32");
	public static final ASN1ObjectIdentifier id_egov_relyingparty = fbca_policies.branch("33");
	public static final ASN1ObjectIdentifier id_egov_metasigner = fbca_policies.branch("34");
	public static final ASN1ObjectIdentifier id_egov_metasigner_hardware = fbca_policies.branch("35");

	/*
	 * National Institute Of Standards And Technology Registered Objects
	 * Two objects have been registered with the National Institute of Standards and Technology PKI policies. The first object is an arc for NIST policies.
	 * 
	 * -- the NIST policy arc
	 * nist-policies OBJECT IDENTIFIER ::= { csor-certpolicy 4 }
	 */
	public static final ASN1ObjectIdentifier nist_policies = csor_certpolicy.branch("4");

	/*
	 * -- the nist policy OIDs
	 * 
	 * 	The following policy is defined in the document: "Basic Level NIST Certificate Policy".
	 */
	public static final ASN1ObjectIdentifier nist_cp1 = nist_policies.branch("1");
	
	/*
	 * U.S. Treasury Department's Registered Objects
	 * Ten objects have been registered to support the U.S. Treasury Department's PKI. The first object is an arc for Treasury policies.
	 * 
	 * -- the Treasury policy arc
	 * treasury-policies OBJECT IDENTIFIER ::= { csor-certpolicy 5 }
	 */
	public static final ASN1ObjectIdentifier treasury_policies = csor_certpolicy.branch("5");

	/*
	 * -- the treasury policy OIDs
	 * 
	 * The following object is the FMS PKI policy. The FMS policy is defined in Certificate Policy CP-1 for FMS Public Key Certificates in Unclassified Environments (draft).
	 */
	public static final ASN1ObjectIdentifier treasury_cp1 = treasury_policies.branch("1");

	/*
	 * The following seven policies will be defined in the US Treasury Certificate Policy which is currently being updated.
	 */
	public static final ASN1ObjectIdentifier id_treasury_certpcy_rudimentary = treasury_policies.branch("2");
	public static final ASN1ObjectIdentifier id_treasury_certpcy_basicindividual = treasury_policies.branch("3");
	public static final ASN1ObjectIdentifier id_treasury_certpcy_basicorganizational = treasury_policies.branch("8");
	public static final ASN1ObjectIdentifier id_treasury_certpcy_medium = treasury_policies.branch("7");
	public static final ASN1ObjectIdentifier id_treasury_certpcy_mediumhardware = treasury_policies.branch("4");
	public static final ASN1ObjectIdentifier id_treasury_certpcy_high = treasury_policies.branch("5");
	public static final ASN1ObjectIdentifier id_treacertpcy_internalnpe = treasury_policies.branch("9");
	
	/*
	 * The following policy is defined in the "Certificate Policy for the Internal Revenue Service (IRS) Secure Messaging" document.
	 */
	public static final ASN1ObjectIdentifier id_us_irs_securemail = treasury_policies.branch("6");


/*	TODO: Finish the remainder of the CSOR
 * 
 * 	State Department Registered Objects
	Seven objects have been registered to support the U.S. State Department PKI. The first object is an arc for State Department policies.

	-- the State policy arc
	state-policies OBJECT IDENTIFIER ::= { csor-certpolicy 6 }

	-- the state policy OIDs

	The following objects are defined in the "United States Department of State X.509 Certificate Policy". (This document is currently not publicly available.)

	2.16.840.1.101.3.2.1.6.1	state-basic
	2.16.840.1.101.3.2.1.6.2	state-low
	2.16.840.1.101.3.2.1.6.3	state-moderate
	2.16.840.1.101.3.2.1.6.4	state-high
	The following objects have been assigned to this agency; however, we do not have the agency Certificate Profile associated with this OID.

	2.16.840.1.101.3.2.1.6.12	state-certpcy-mediumHardware
	2.16.840.1.101.3.2.1.6.14	state-certpcy-citizen-and-commerce
	2.16.840.1.101.3.2.1.6.37	state-certpcy-mediumDevice
	2.16.840.1.101.3.2.1.6.38	state-certpcy-mediumDeviceHardware
	The following object is defined in the "Machine Readable Travel Document (MRTD) PKI X.509 Certificate Policy Version 1.1". (This document is currently not publicly available.)

	2.16.840.1.101.3.2.1.6.100	state-mrtd
	Back to Top
	Federal Deposit Insurance Corporation Registered Objects
	Five objects have been registered to support the Federal Deposit Insurance Corporation PKI. The first object is an arc for FDIC policies.

	-- the FDIC policy arc
	fdic-policies OBJECT IDENTIFIER ::= { csor-certpolicy 7 }

	-- the fdic policy OIDs

	The following four policies can be defined in the "Certificate Policy for the Federal Deposit Insurance Corporation" document.  (This document is currently not publicly available.)

	2.16.840.1.101.3.2.1.7.1	fdic-basic
	2.16.840.1.101.3.2.1.7.2	fdic-low
	2.16.840.1.101.3.2.1.7.3	fdic-moderate
	2.16.840.1.101.3.2.1.7.4	fdic-high
	Back to Top
	NFC (National Finance Center) Registered Objects
	Four objects have been registered to support the USDA and NFC PKI. The first object is an arc for USDA-NFC policies.

	-- the NFC policy arc
	nfc-policies OBJECT IDENTIFIER ::= { csor-certpolicy 8}

	-- the nfc policy OIDS

	The following three policies are defined in the "United States Department of Agriculture and National Finance Center Public Key Infrastructure Certificate Policy"

	2.16.840.1.101.3.2.1.8.1	nfc-basicAssurance
	2.16.840.1.101.3.2.1.8.2	nfc-mediumAssurance
	2.16.840.1.101.3.2.1.8.3	nfc-highAssurance
	Back to Top
	Drug Enforcement Administration Registered Objects
	Three objects have been registered to support the DEA PKI. The first object is an arc for DEA policies.

	-- the DEA policy arc
	dea-policies OBJECT IDENTIFIER ::= { csor-certpolicy 9}

	-- the dea policy OIDS

	The following policies have been assigned to this agency; however, we do not have the agency Certificate Profile associated with these OIDs.

	2.16.840.1.101.3.2.1.9.1	dea-csos-cp
	2.16.840.1.101.3.2.1.9.2	dea-epcs-policy
	Back to Top
	DOE (Department Of Energy) Registered Objects
	Five objects have been registered to support the Department of Energy policies for PKI. The first object is an arc for DOE policies.

	-- the DOE policy arc
	doe-policies OBJECT IDENTIFIER ::= { csor-certpolicy 10}

	-- the doe policy OIDS

	The following three policies are defined in the "Certificate Policy CP-1 for DOE Public Key Certificates in Unclassified"

	2.16.840.1.101.3.2.1.10.1	doe-basic
	2.16.840.1.101.3.2.1.10.2	doe-medium
	2.16.840.1.101.3.2.1.10.3	doe-high
	The policy below is defined in the "U.S. Department of Energy Public Key Infrastructure X.509 Certificate Policy" document.

	2.16.840.1.101.3.2.1.10.4	doe-medium-v2
	Back to Top
	DOL (Department Of Labor) Registered Objects
	Three objects have been registered to support the Department of Labor policies for PKI. The first object is an arc for DOL policies.

	-- the DOL policy arc
	dol-policies OBJECT IDENTIFIER ::= { csor-certpolicy 11}

	-- the dol policy OIDS

	These OIDs have been assigned to this agency; however, we do not have the agency Certificate Profile associated with these OIDs.

	2.16.840.1.101.3.2.1.11.1	dol-basic
	2.16.840.1.101.3.2.1.11.2	dol-medium
	Back to Top
	ECA (External Certification Authority) Registered Objects
	Ten objects have been registered to support the ECA policies for PKI. The first object is an arc for ECA policies.

	-- the ECA policy arc
	eca-policies OBJECT IDENTIFIER ::= { csor-certpolicy 12}

	-- the eca policy OIDS

	The following three policies are defined in the "United States Department of Defense External Certification Authority X.509 Certificate Policy"

	2.16.840.1.101.3.2.1.12.1	id-eca-medium
	2.16.840.1.101.3.2.1.12.3	id-eca-medium-token
	2.16.840.1.101.3.2.1.12.2	id-eca-medium-hardware
	2.16.840.1.101.3.2.1.12.4	id-eca-medium-sha256
	2.16.840.1.101.3.2.1.12.5	id-eca-medium-token-sha256
	2.16.840.1.101.3.2.1.12.6	id-eca-medium-hardware-pivi
	2.16.840.1.101.3.2.1.12.7	id-eca-cardauth-pivi
	2.16.840.1.101.3.2.1.12.8	id-eca-contentsigning-pivi
	2.16.840.1.101.3.2.1.12.9	id-eca-medium-device-sha256
	Back to Top
	FDA (Food And Drug Administration) Registered Objects
	Thirteen objects have been registered to support the Food and Drug Administration policies for PKI. The first object is an arc for FDA policies.

	id-ORApki-policies OBJECT IDENTIFIER ::= { csor-certpolicy 13}

	The following policy is defined in the "X.509 Certificate Policy for the Food and Drug Administration (FDA) Office"

	2.16.840.1.101.3.2.1.13.1	id-ORApki-assurance-test
	2.16.840.1.101.3.2.1.13.2	id-ORApki-assurance-basic
	2.16.840.1.101.3.2.1.13.3	id-ORApki-assurance-medium
	2.16.840.1.101.3.2.1.13.4	id-ORApki-assurance-high
	The following objects have been assigned to this agency and are defined in the "HHS Public Key Infrastructure X.509 Certificate Policy for HHS Domain Devices, Ver. 1.5"

	2.16.840.1.101.3.2.1.13.5	id-pki-HHSdomains
	2.16.840.1.101.3.2.1.13.5.1	id-HHSdomains-LoA
	2.16.840.1.101.3.2.1.13.5.1.1	id-HHSdomains-assurance-basic
	2.16.840.1.101.3.2.1.13.5.1.2	id-HHSdomains-assurance-high

	2.16.840.1.101.3.2.1.13.5.2	id-HHSdomains-OPDIVpolicies
	2.16.840.1.101.3.2.1.13.5.2.1	id-pki-IHSdomains
	2.16.840.1.101.3.2.1.13.5.2.2	id-pki-NIHdomains
	2.16.840.1.101.3.2.1.13.5.2.3	id-pki-FDAdomains
	 

	Back to Top
	Citizen And Commerce Registered Objects
	Three objects have been registered to support the Citizen and Commerce policies for PKI. The first object is an arc for the Citizen and Commerce policies.

	-- the Citizen and Commerce policy arc
	citizen-and-commerce-policies OBJECT IDENTIFIER ::= { csor-certpolicy 14}

	-- the citizen-and-commerce policy OIDS

	The following two policies are defined in the "Citizen and Commerce Certificate Policy" document.

	2.16.840.1.101.3.2.1.14.1	citizen-and-commerce-provisional
	2.16.840.1.101.3.2.1.14.2	citizen-and-commerce-approved
	Back to Top
	Department Of Homeland Security Registered Objects
	Twenty-three objects have been registered to support the Department of Homeland Security policies for PKI. The first object is an arc for the DHS policies.

	dhs-policies OBJECT IDENTIFIER ::= { csor-certpolicy 15}

	The following arc is reserved for private DHS certificate content and PKI-protected message formats:

	2.16.840.1.101.3.2.1.15.0	id-dhs-pkiObjects
	The following OID is defined for use in the extended key usage extension:

	2.16.840.1.101.3.2.1.15.0.1

	id-dhs-USVISITsigner
	The following OID is assigned to the ASN.1 module that defines the eContentTypes and value for the extendedKeyUsage extension:

	2.16.840.1.101.3.2.1.15.0.2

	id-dhs-MRTDValidationV4
	The following OIDs are assigned to DHS eContentTypes for use with Cryptographic Message Syntax object formats:

	2.16.840.1.101.3.2.1.15.0.3

	id-dhs-ValidationList
	2.16.840.1.101.3.2.1.15.0.4

	id-dhs-CertStatus
	2.16.840.1.101.3.2.1.15.0.5

	id-dhs-CountryStatus
	The following seven policies are defined within the "X.509 Certificate Policy for the Department of Homeland Security Public Key Infrastructure" document.

	2.16.840.1.101.3.2.1.15.1	id-dhs-certpcy-rudimentary
	2.16.840.1.101.3.2.1.15.2	id-dhs-certpcy-basic
	2.16.840.1.101.3.2.1.15.3	id-dhs-certpcy-medium
	2.16.840.1.101.3.2.1.15.4	id-dhs-certpcy-high
	2.16.840.1.101.3.2.1.15.5	id-dhs-certpcy-mediumHardware
	2.16.840.1.101.3.2.1.15.6	id-dhs-certpcy-cardAuth
	2.16.840.1.101.3.2.1.15.7	id-dhs-certpcy-internalBasic
	The following seven test policies are defined within the "X.509 Certificate Policy for the Department of Homeland Security Public Key Infrastructure" document to support pilots and testing. These policies should never be inserted in "real" certificates, and no relying party should ever accept such a certificate to implement security services in a "real" application!

	2.16.840.1.101.3.2.1.15.31	id-dhs-certpcy-testRudimentary
	2.16.840.1.101.3.2.1.15.32	id-dhs-certpcy-testBasic
	2.16.840.1.101.3.2.1.15.33	id-dhs-certpcy-testMedium
	2.16.840.1.101.3.2.1.15.34	id-dhs-certpcy-testHigh
	2.16.840.1.101.3.2.1.15.35	id-dhs-certpcy-testMediumHardware
	2.16.840.1.101.3.2.1.15.36	id-dhs-certpcy-testCardAuth
	2.16.840.1.101.3.2.1.15.37	id-dhs-certpcy-testInternalBasic
	The following policy is defined within the "Department of Homeland Security Public Key Infrastructure X.509 Internal Use Non Person Entity Certificate Policy” document:

	2.16.840.1.101.3.2.1.15.8

	id-dhs-certpcy-internalNpe
	The following test policy is defined within the "Department of Homeland Security Public Key Infrastructure X.509 Internal Use Non Person Entity Certificate Policy” document to support pilots and testing. These policies should never be inserted in "real" certificates, and no relying party should ever accept such a certificate to implement security services in a "real" application!:

	2.16.840.1.101.3.2.1.15.38

	id-dhs-certpcy-testInternalNpe
	 

	Back to Top
	Department Of Justice Registered Objects
	Eight objects have been registered to support the Department of Justice policies for PKI. The first object is an arc for the DOJ policies.

	-- the DOJ policy arc
	id-doj-policies OBJECT IDENTIFIER ::= { csor-certpolicy 16}

	-- the doj policy OIDS

	The following five policies are defined in the "Department of Justice Public Key Infrastructure X.509 Certificate Policy" document.

	2.16.840.1.101.3.2.1.16.1	id-doj-Class1
	2.16.840.1.101.3.2.1.16.2	id-doj-Class2
	2.16.840.1.101.3.2.1.16.3	id-doj-Class3
	2.16.840.1.101.3.2.1.16.4	id-doj-Class4
	2.16.840.1.101.3.2.1.16.5	id-doj-Class5
	The following two policies are defined in the "X.509 Certificate Policy for the Federal Bureau of Investigation Public Key Infrastructure.

	2.16.840.1.101.3.2.1.16.6.1	id-fbi-mediumAssurance
	2.16.840.1.101.3.2.1.16.6.2	id-fbi-highAssurance
	Back to Top
	Government Printing Office Registered Objects
	Six objects have been registered to support the Government Printing Office policies for PKI. The first object is an arc for the GPO policies.

	-- the GPO policy arc
	id-gpo-policies OBJECT IDENTIFIER ::= { csor-certpolicy 17}

	-- the gpo policy OIDS

	The following policies are defined in the "X.509 Certificate Policy for the Government Printing Office Certification Authority".

	2.16.840.1.101.3.2.1.17.1	id-gpo-medium
	2.16.840.1.101.3.2.1.17.2	id-gpo-medium-hardware
	2.16.840.1.101.3.2.1.17.3	id-gpo-certpcy-devices
	2.16.840.1.101.3.2.1.17.4	id-gpo-certpcy-authentication
	2.16.840.1.101.3.2.1.17.5	id-gpo-certpcy-cardAuth
	Back to Top
	Nuclear Regulatory Commission Registered Objects
	Three objects have been registered to support the Nuclear Regulatory Commission policies for PKI. The first object is an arc for the NRC policies.

	-- the NRC policy arc
	id-nrc-policies OBJECT IDENTIFIER ::= { csor-certpolicy 18}

	-- the nrc policy OIDS

	The following policy are defined in the "U.S. Nuclear Regulatory Commission Certificate Policy for Level 3 Assurance Addendum to the VTN CP" document (not publicly available).

	2.16.840.1.101.3.2.1.18.1	id-nrc-level3
	The following policy are defined in the "U.S. Nuclear Regulatory Commission Certificate Policy for Level 2 Assurance Addendum to the VTN CP" document (not publicly available).

	2.16.840.1.101.3.2.1.18.2	id-nrc-level2
	 

	Back to Top
	Department Of Interior Registered Objects
	Three objects have been registered to support the Department of Interior policies for PKI. The first object is an arc for the DOI policies.

	-- the DOI policy arc
	id-doi-policies OBJECT IDENTIFIER ::= { csor-certpolicy 19}

	-- the doi policy OIDS

	These OIDs have been assigned to this agency; however, we do not have the agency Certificate Profile associated with these OIDs.

	2.16.840.1.101.3.2.1.19.1	id-doi-basic
	2.16.840.1.101.3.2.1.19.2	id-doi-medium
	Back to Top
	U.S. Postal Service Registered Objects
	Nineteen objects have been registered to support the U.S. Postal Service policies for PKI. The first object is an arc for the USPS policies.

	-- the USPS policy arc
	id-usps-policies OBJECT IDENTIFIER ::= { csor-certpolicy 20}

	-- the usps policy OIDS

	These OIDs have been assigned to this agency; however, the Certificate Policy is still in draft format.

	2.16.840.1.101.3.2.1.20.1	id-usps-certpcy-rudimentaryAssurance
	2.16.840.1.101.3.2.1.20.2	id-usps-certpcy-basicAssurance
	2.16.840.1.101.3.2.1.20.3	id-usps-certpcy-mediumAssurance
	2.16.840.1.101.3.2.1.20.12	id-usps-certpcy-mediumHardware
	2.16.840.1.101.3.2.1.20.18	id-usps-certpcy-pivi-hardware
	2.16.840.1.101.3.2.1.20.19	id-usps-certpcy-pivi-cardAuth
	2.16.840.1.101.3.2.1.20.20	id-usps-certpcy-pivi-contentSigning
	2.16.840.1.101.3.2.1.20.37	id-usps-certpcy-mediumDevice
	2.16.840.1.101.3.2.1.20.38	id-usps-certpcy-mediumDeviceHardware
	The following OIDs have been assigned to this agency as Test OIDs to mirror the above.

	2.16.840.1.101.3.2.1.20.4.1	id-usps-Testcertpcy-rudimentaryAssurance
	2.16.840.1.101.3.2.1.20.4.2	id-usps-Testcertpcy-basicAssurance
	2.16.840.1.101.3.2.1.20.4.3	id-usps-Testcertpcy-mediumAssurance
	2.16.840.1.101.3.2.1.20.4.12	id-usps-Testcertpcy-mediumHardware
	2.16.840.1.101.3.2.1.20.4.18	id-usps-Testcertpcy-pivi-hardware
	2.16.840.1.101.3.2.1.20.4.19	id-usps-Testcertpcy-pivi-cardAuth
	2.16.840.1.101.3.2.1.20.4.20	id-usps-Testcertpcy-pivi-contentSigning
	2.16.840.1.101.3.2.1.20.4.37	id-usps-Testcertpcy-mediumDevice
	2.16.840.1.101.3.2.1.20.4.38	id-usps-Testcertpcy-mediumDeviceHardware
	Back to Top

	Committee On National Security Systems Registered Objects
	This arc is maintained by CNSS. The first object is an arc for the CNSS policies.

	-- the CNSS policy arc
	id-cnss-policies OBJECT IDENTIFIER ::= { csor-certpolicy 21}

	The OIDs assigned by this agency can be found in the Instruction for National Security Systems PKI X.509 Certificate Policy.

	Back to Top
	Federal Energy Regulatory Commission Registered Objects
	Six objects have been registered to support the Federal Energy Regulatory Commission policies for PKI. The first object is an arc for the FERC policies.

	-- the FERC policy arc
	id-ferc-policies OBJECT IDENTIFIER ::= { csor-certpolicy 22}

	-- the ferc policy OIDS

	These OIDs have been assigned to this agency; however, the Certificate Policy is not publicly available.

	2.16.840.1.101.3.2.1.22.1	id-ferc-Test
	2.16.840.1.101.3.2.1.22.2	id-ferc-Basic
	2.16.840.1.101.3.2.1.22.3	id-ferc-Medium
	2.16.840.1.101.3.2.1.22.4	id-ferc-Medium-Hardware
	2.16.840.1.101.3.2.1.22.5	id-ferc-High
	Back to Top
	U.S. Agency For International Development
	Three objects have been registered to support the U.S. Agency for International Development policies for PKI. The first object is an arc for the USAID policies.

	-- the USAID policy arc
	id-usaid-policies OBJECT IDENTIFIER ::= { csor-certpolicy 23}

	-- the usaid policy OIDS

	These OIDs have been assigned to this agency; however, the Certificate Policy is not publicly available.

	2.16.840.1.101.3.2.1.23.1	id-usaid-basic
	2.16.840.1.101.3.2.1.23.2	id-usaid-medium
	Back to Top
	PKI Pilots And Testing Registered Objects
	There are 257 objects registered to support PKI pilots and testing. These objects define an arc for policies associated and 256 distinct policies. These policies should never be inserted in "real" certificates, and no relying party should ever accept such a certificate to implement security services in a "real" application! Note that the 256 policies are all equivalent and are defined within the "Test Certificate Policy to Support PKI Pilots and Testing" document.

	-- test policy arc

	csor-test-policies OBJECT IDENTIFIER ::= { 2 16 840 1 101 3 2 1 48 }

	-- test policy OIDs

	2.16.840.1.101.3.2.1.48.1	test1
	2.16.840.1.101.3.2.1.48.2	test2
	2.16.840.1.101.3.2.1.48.3	test3
	2.16.840.1.101.3.2.1.48.4	test4
	2.16.840.1.101.3.2.1.48.5	test5
	2.16.840.1.101.3.2.1.48.6	test6
	2.16.840.1.101.3.2.1.48.7	test7
	2.16.840.1.101.3.2.1.48.8	test8
	2.16.840.1.101.3.2.1.48.9	test9
	2.16.840.1.101.3.2.1.48.10	test10
	.................


	2.16.840.1.101.3.2.1.48.254	test254
	2.16.840.1.101.3.2.1.48.255	test255
	2.16.840.1.101.3.2.1.48.256	test256
*/	
	

}
