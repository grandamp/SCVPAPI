package org.keysupport.fpki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/*
 * This interface is intended to provide a java
 * representation of the NIST Computer Security
 * Object Registry (CSOR) for the Federal PKI
 * policies: 
 * 
 * http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/pki_registration.html
 * 
 * TODO: Find an easier way to keep this in sync with the CSOR
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


	/*
	 * State Department Registered Objects
	 * Seven objects have been registered to support the U.S. State Department PKI. The first object is an arc for State Department policies.
	 *
	 *-- the State policy arc
	 *
	 * state-policies OBJECT IDENTIFIER ::= { csor-certpolicy 6 }
	 */
	public static final ASN1ObjectIdentifier state_policies = csor_certpolicy.branch("6");

	/*
	 * -- the state policy OIDs
	 *
	 * The following objects are defined in the "United States Department of State X.509 Certificate Policy". (This document is currently not publicly available.)
	 */
	public static final ASN1ObjectIdentifier state_basic = state_policies.branch("1");
	public static final ASN1ObjectIdentifier state_low = state_policies.branch("2");
	public static final ASN1ObjectIdentifier state_moderate = state_policies.branch("3");
	public static final ASN1ObjectIdentifier state_high = state_policies.branch("4");

	/*
	 * The following objects have been assigned to this agency; however, we do not have the agency Certificate Profile associated with this OID.
	 */
	public static final ASN1ObjectIdentifier state_certpcy_mediumHardware = state_policies.branch("12");
	public static final ASN1ObjectIdentifier state_certpcy_citizen_and_commerce = state_policies.branch("14");
	public static final ASN1ObjectIdentifier state_certpcy_mediumDevice = state_policies.branch("37");
	public static final ASN1ObjectIdentifier state_certpcy_mediumDeviceHardware = state_policies.branch("38");

	/*
	 * The following object is defined in the "Machine Readable Travel Document (MRTD) PKI X.509 Certificate Policy Version 1.1". (This document is currently not publicly available.)
	 */
	public static final ASN1ObjectIdentifier state_mrtd = state_policies.branch("100");

	/* Federal Deposit Insurance Corporation Registered Objects
	 * Five objects have been registered to support the Federal Deposit Insurance Corporation PKI. The first object is an arc for FDIC policies.
	 * 
	 * -- the FDIC policy arc
	 * 
	 * fdic-policies OBJECT IDENTIFIER ::= { csor-certpolicy 7 }
	 */
	public static final ASN1ObjectIdentifier fdic_policies = csor_certpolicy.branch("7");
	
	/*
	 * -- the fdic policy OIDs
	 * 
	 * The following four policies can be defined in the "Certificate Policy for the Federal Deposit Insurance Corporation" document.  (This document is currently not publicly available.)
	 */
	public static final ASN1ObjectIdentifier fdic_basic = fdic_policies.branch("1");
	public static final ASN1ObjectIdentifier fdic_low = fdic_policies.branch("2");
	public static final ASN1ObjectIdentifier fdic_moderate = fdic_policies.branch("3");
	public static final ASN1ObjectIdentifier fdic_high = fdic_policies.branch("4");

	/*
	 * NFC (National Finance Center) Registered Objects
	 * Four objects have been registered to support the USDA and NFC PKI. The first object is an arc for USDA-NFC policies.
	 * 
	 * -- the NFC policy arc
	 *  nfc-policies OBJECT IDENTIFIER ::= { csor-certpolicy 8}
	 */
	public static final ASN1ObjectIdentifier nfc_policies = csor_certpolicy.branch("8");

	/*
	 * -- the nfc policy OIDS
	 * 
	 * The following three policies are defined in the "United States Department of Agriculture and National Finance Center Public Key Infrastructure Certificate Policy"
	 */
	public static final ASN1ObjectIdentifier nfc_basicAssurance = nfc_policies.branch("1");
	public static final ASN1ObjectIdentifier nfc_mediumAssurance = nfc_policies.branch("2");
	public static final ASN1ObjectIdentifier nfc_highAssurance = nfc_policies.branch("3");

	/*
	 * Drug Enforcement Administration Registered Objects
	 * Three objects have been registered to support the DEA PKI. The first object is an arc for DEA policies.
	 * 
	 * 	-- the DEA policy arc
	 * dea-policies OBJECT IDENTIFIER ::= { csor-certpolicy 9}
	 */
	public static final ASN1ObjectIdentifier dea_policies = csor_certpolicy.branch("9");

	/*
	 * -- the dea policy OIDS
	 * 
	 * The following policies have been assigned to this agency; however, we do not have the agency Certificate Profile associated with these OIDs.
	 */
	public static final ASN1ObjectIdentifier dea_csos_cp = dea_policies.branch("1");
	public static final ASN1ObjectIdentifier dea_epcs_policy = dea_policies.branch("2");

	/*
	 * DOE (Department Of Energy) Registered Objects
	 * Five objects have been registered to support the Department of Energy policies for PKI. The first object is an arc for DOE policies.
	 * 
	 * -- the DOE policy arc
	 * doe-policies OBJECT IDENTIFIER ::= { csor-certpolicy 10}
	 */
	public static final ASN1ObjectIdentifier doe_policies = csor_certpolicy.branch("10");

	/*
	 * -- the doe policy OIDS
	 * 
	 * The following three policies are defined in the "Certificate Policy CP-1 for DOE Public Key Certificates in Unclassified"
	 */
	public static final ASN1ObjectIdentifier doe_basic = doe_policies.branch("1");
	public static final ASN1ObjectIdentifier doe_medium = doe_policies.branch("2");
	public static final ASN1ObjectIdentifier doe_high = doe_policies.branch("3");

	/*
	 * The policy below is defined in the "U.S. Department of Energy Public Key Infrastructure X.509 Certificate Policy" document.
	 */
	public static final ASN1ObjectIdentifier doe_medium_v2 = doe_policies.branch("4");

	/* 
	 * DOL (Department Of Labor) Registered Objects
	 * Three objects have been registered to support the Department of Labor policies for PKI. The first object is an arc for DOL policies.
	 * 
	 * -- the DOL policy arc
	 * dol-policies OBJECT IDENTIFIER ::= { csor-certpolicy 11}
	 */
	public static final ASN1ObjectIdentifier dol_policies = csor_certpolicy.branch("11");
	
	/*
	 * -- the dol policy OIDS
	 *
	 * These OIDs have been assigned to this agency; however, we do not have the agency Certificate Profile associated with these OIDs.
	 */
	public static final ASN1ObjectIdentifier dol_basic = dol_policies.branch("1");
	public static final ASN1ObjectIdentifier dol_medium = dol_policies.branch("2");

	/*
	 * ECA (External Certification Authority) Registered Objects
	 * Ten objects have been registered to support the ECA policies for PKI. The first object is an arc for ECA policies.
	 * 
	 * -- the ECA policy arc
	 * eca-policies OBJECT IDENTIFIER ::= { csor-certpolicy 12}
	 */
	public static final ASN1ObjectIdentifier eca_policies = csor_certpolicy.branch("12");

	/*
	 * -- the eca policy OIDS
	 * 
	 * The following three policies are defined in the "United States Department of Defense External Certification Authority X.509 Certificate Policy"
	 */
	public static final ASN1ObjectIdentifier eca_medium = eca_policies.branch("1");
	public static final ASN1ObjectIdentifier eca_medium_hardware = eca_policies.branch("2");
	public static final ASN1ObjectIdentifier eca_medium_token = eca_policies.branch("3");
	public static final ASN1ObjectIdentifier eca_medium_sha256 = eca_policies.branch("4");
	public static final ASN1ObjectIdentifier eca_medium_token_sha256 = eca_policies.branch("5");
	public static final ASN1ObjectIdentifier eca_medium_hardware_pivi = eca_policies.branch("6");
	public static final ASN1ObjectIdentifier eca_cardauth_pivi = eca_policies.branch("7");
	public static final ASN1ObjectIdentifier eca_contentsigning_pivi = eca_policies.branch("8");
	public static final ASN1ObjectIdentifier eca_medium_device_sha256 = eca_policies.branch("9");

	/*
	 * FDA (Food And Drug Administration) Registered Objects
	 * Thirteen objects have been registered to support the Food and Drug Administration policies for PKI. The first object is an arc for FDA policies.
	 * 
	 * 	id-ORApki-policies OBJECT IDENTIFIER ::= { csor-certpolicy 13}
	 */
	public static final ASN1ObjectIdentifier orapki_policies = csor_certpolicy.branch("13");

	/* 
	 * The following policy is defined in the "X.509 Certificate Policy for the Food and Drug Administration (FDA) Office"
	 */
	public static final ASN1ObjectIdentifier orapki_test = orapki_policies.branch("1");
	public static final ASN1ObjectIdentifier orapki_basic = orapki_policies.branch("2");
	public static final ASN1ObjectIdentifier orapki_medium = orapki_policies.branch("3");
	public static final ASN1ObjectIdentifier orapki_high = orapki_policies.branch("4");

	/*
	 * The following objects have been assigned to this agency and are defined in the "HHS Public Key Infrastructure X.509 Certificate Policy for HHS Domain Devices, Ver. 1.5"
	 */
	public static final ASN1ObjectIdentifier hhs_domains = orapki_policies.branch("5");
	public static final ASN1ObjectIdentifier hhs_domains_loa = hhs_domains.branch("1");
	public static final ASN1ObjectIdentifier hhs_domains_loa_basic = hhs_domains_loa.branch("1");
	public static final ASN1ObjectIdentifier hhs_domains_loa_high = hhs_domains_loa.branch("2");
	public static final ASN1ObjectIdentifier hhs_domains_pki = hhs_domains.branch("2");
	public static final ASN1ObjectIdentifier hhs_domains_pki_ihs = hhs_domains_pki.branch("1");
	public static final ASN1ObjectIdentifier hhs_domains_pki_nih = hhs_domains_pki.branch("2");
	public static final ASN1ObjectIdentifier hhs_domains_pki_fda = hhs_domains_pki.branch("3");
	
	/*
	 * Citizen And Commerce Registered Objects
	 * Three objects have been registered to support the Citizen and Commerce policies for PKI. The first object is an arc for the Citizen and Commerce policies.
	 * 
	 * -- the Citizen and Commerce policy arc
	 * citizen-and-commerce-policies OBJECT IDENTIFIER ::= { csor-certpolicy 14}
	 */
	public static final ASN1ObjectIdentifier candc_policies = csor_certpolicy.branch("14");

	/*
	 * -- the citizen-and-commerce policy OIDS
	 * 
	 * The following two policies are defined in the "Citizen and Commerce Certificate Policy" document.
	 */
	public static final ASN1ObjectIdentifier candc_provisional = candc_policies.branch("1");
	public static final ASN1ObjectIdentifier candc_approved = candc_policies.branch("2");

	/*
	 * Department Of Homeland Security Registered Objects
	 * Twenty-three objects have been registered to support the Department of Homeland Security policies for PKI. The first object is an arc for the DHS policies.
	 * 
	 * dhs-policies OBJECT IDENTIFIER ::= { csor-certpolicy 15}
	 */
	public static final ASN1ObjectIdentifier dhs_policies = csor_certpolicy.branch("15");
	
	/*
	 * The following arc is reserved for private DHS certificate content and PKI-protected message formats:
	 */
	public static final ASN1ObjectIdentifier dhs_pki_objects = dhs_policies.branch("0");

	/*
	 * The following OID is defined for use in the extended key usage extension:
	 */
	public static final ASN1ObjectIdentifier dhs_usvisit_signer = dhs_pki_objects.branch("1");

	/*
	 * The following OID is assigned to the ASN.1 module that defines the eContentTypes and value for the extendedKeyUsage extension:
	 */
	public static final ASN1ObjectIdentifier dhs_mrtdval_v4 = dhs_pki_objects.branch("2");

	/*
	 * The following OIDs are assigned to DHS eContentTypes for use with Cryptographic Message Syntax object formats:
	 */
	public static final ASN1ObjectIdentifier dhs_validation_list = dhs_pki_objects.branch("3");
	public static final ASN1ObjectIdentifier dhs_cert_status = dhs_pki_objects.branch("4");
	public static final ASN1ObjectIdentifier dhs_country_status = dhs_pki_objects.branch("5");

	/*
	 * The following seven policies are defined within the "X.509 Certificate Policy for the Department of Homeland Security Public Key Infrastructure" document.
	 */
	public static final ASN1ObjectIdentifier dhs_rudimentary = dhs_policies.branch("1");
	public static final ASN1ObjectIdentifier dhs_basic = dhs_policies.branch("2");
	public static final ASN1ObjectIdentifier dhs_medium = dhs_policies.branch("3");
	public static final ASN1ObjectIdentifier dhs_high = dhs_policies.branch("4");
	public static final ASN1ObjectIdentifier dhs_medium_hardware = dhs_policies.branch("5");
	public static final ASN1ObjectIdentifier dhs_cardauth = dhs_policies.branch("6");
	public static final ASN1ObjectIdentifier dhs_internal_basic = dhs_policies.branch("7");

	/*
	 * The following seven test policies are defined within the "X.509 Certificate Policy for the Department of Homeland Security Public Key Infrastructure" document to support pilots and testing. These policies should never be inserted in "real" certificates, and no relying party should ever accept such a certificate to implement security services in a "real" application!
	 */
	public static final ASN1ObjectIdentifier dhs_test_rudimentary = dhs_policies.branch("31");
	public static final ASN1ObjectIdentifier dhs_test_basic = dhs_policies.branch("32");
	public static final ASN1ObjectIdentifier dhs_test_medium = dhs_policies.branch("33");
	public static final ASN1ObjectIdentifier dhs_test_high = dhs_policies.branch("34");
	public static final ASN1ObjectIdentifier dhs_test_medium_hardware = dhs_policies.branch("35");
	public static final ASN1ObjectIdentifier dhs_test_cardauth = dhs_policies.branch("36");
	public static final ASN1ObjectIdentifier dhs_test_internal_basic = dhs_policies.branch("37");

	/*
	 * The following policy is defined within the "Department of Homeland Security Public Key Infrastructure X.509 Internal Use Non Person Entity Certificate Policy” document:
	 */
	public static final ASN1ObjectIdentifier dhs_internal_npe = dhs_policies.branch("8");

	/*
	 * The following test policy is defined within the "Department of Homeland Security Public Key Infrastructure X.509 Internal Use Non Person Entity Certificate Policy” document to support pilots and testing. These policies should never be inserted in "real" certificates, and no relying party should ever accept such a certificate to implement security services in a "real" application!:
	 */
	public static final ASN1ObjectIdentifier dhs_test_internal_npe = dhs_policies.branch("38");

	/*
	 * Department Of Justice Registered Objects
	 * Eight objects have been registered to support the Department of Justice policies for PKI. The first object is an arc for the DOJ policies.
	 * 
	 * -- the DOJ policy arc
	 * id-doj-policies OBJECT IDENTIFIER ::= { csor-certpolicy 16}
	 */
	public static final ASN1ObjectIdentifier doj_policies = csor_certpolicy.branch("16");

	/*
	 * -- the doj policy OIDS
	 * 
	 * The following five policies are defined in the "Department of Justice Public Key Infrastructure X.509 Certificate Policy" document.
	 */
	public static final ASN1ObjectIdentifier doj_class1 = doj_policies.branch("1");
	public static final ASN1ObjectIdentifier doj_class2 = doj_policies.branch("2");
	public static final ASN1ObjectIdentifier doj_class3 = doj_policies.branch("3");
	public static final ASN1ObjectIdentifier doj_class4 = doj_policies.branch("4");
	public static final ASN1ObjectIdentifier doj_class5 = doj_policies.branch("5");

	/*
	 * The following two policies are defined in the "X.509 Certificate Policy for the Federal Bureau of Investigation Public Key Infrastructure.
	 */
	public static final ASN1ObjectIdentifier fbi_policies = doj_policies.branch("6");
	public static final ASN1ObjectIdentifier fbi_medium = fbi_policies.branch("1");
	public static final ASN1ObjectIdentifier fbi_high = fbi_policies.branch("2");

	/*
	 * Government Printing Office Registered Objects
	 * Six objects have been registered to support the Government Printing Office policies for PKI. The first object is an arc for the GPO policies.
	 * 
	 * -- the GPO policy arc
	 * id-gpo-policies OBJECT IDENTIFIER ::= { csor-certpolicy 17}
	 */
	public static final ASN1ObjectIdentifier gpo_policies = csor_certpolicy.branch("17");

	/*
	 * -- the gpo policy OIDS
	 * 
	 * The following policies are defined in the "X.509 Certificate Policy for the Government Printing Office Certification Authority".
	 */
	public static final ASN1ObjectIdentifier gpo_medium = gpo_policies.branch("1");
	public static final ASN1ObjectIdentifier gpo_medium_hardware = gpo_policies.branch("2");
	public static final ASN1ObjectIdentifier gpo_devices = gpo_policies.branch("3");
	public static final ASN1ObjectIdentifier gpo_authentication = gpo_policies.branch("4");
	public static final ASN1ObjectIdentifier gpo_cardauth = gpo_policies.branch("5");

	/*
	 * Nuclear Regulatory Commission Registered Objects
	 * Three objects have been registered to support the Nuclear Regulatory Commission policies for PKI. The first object is an arc for the NRC policies.
	 * 
	 * -- the NRC policy arc
	 * id-nrc-policies OBJECT IDENTIFIER ::= { csor-certpolicy 18}
	 */
	public static final ASN1ObjectIdentifier nrc_policies = csor_certpolicy.branch("18");

	/*
	 * -- the nrc policy OIDS
	 * 
	 * The following policy are defined in the "U.S. Nuclear Regulatory Commission Certificate Policy for Level 3 Assurance Addendum to the VTN CP" document (not publicly available).
	 */
	public static final ASN1ObjectIdentifier nrc_level3 = nrc_policies.branch("1");
	
	/*
	 * The following policy are defined in the "U.S. Nuclear Regulatory Commission Certificate Policy for Level 2 Assurance Addendum to the VTN CP" document (not publicly available).
	 */
	public static final ASN1ObjectIdentifier nrc_level2 = nrc_policies.branch("2");

	/*
	 * Department Of Interior Registered Objects
	 * Three objects have been registered to support the Department of Interior policies for PKI. The first object is an arc for the DOI policies.
	 * 
	 * -- the DOI policy arc
	 * id-doi-policies OBJECT IDENTIFIER ::= { csor-certpolicy 19}
	 */
	public static final ASN1ObjectIdentifier doi_policies = csor_certpolicy.branch("19");
	
	/*
	 * -- the doi policy OIDS
	 * 
	 * These OIDs have been assigned to this agency; however, we do not have the agency Certificate Profile associated with these OIDs.
	 */
	public static final ASN1ObjectIdentifier doi_basic = doi_policies.branch("1");
	public static final ASN1ObjectIdentifier doi_medium = doi_policies.branch("2");

	/*
	 * U.S. Postal Service Registered Objects
	 * Nineteen objects have been registered to support the U.S. Postal Service policies for PKI. The first object is an arc for the USPS policies.
	 * 
	 * -- the USPS policy arc
	 * id-usps-policies OBJECT IDENTIFIER ::= { csor-certpolicy 20}
	 */
	public static final ASN1ObjectIdentifier usps_policies = csor_certpolicy.branch("20");

	/*
	 * -- the usps policy OIDS
	 * 
	 * These OIDs have been assigned to this agency; however, the Certificate Policy is still in draft format.
	 */
	public static final ASN1ObjectIdentifier usps_rudimentary = usps_policies.branch("1");
	public static final ASN1ObjectIdentifier usps_basic = usps_policies.branch("2");
	public static final ASN1ObjectIdentifier usps_medium = usps_policies.branch("3");
	public static final ASN1ObjectIdentifier usps_medium_hardware = usps_policies.branch("12");
	public static final ASN1ObjectIdentifier usps_pivi_hardware = usps_policies.branch("18");
	public static final ASN1ObjectIdentifier usps_pivi_cardauth = usps_policies.branch("19");
	public static final ASN1ObjectIdentifier usps_pivi_content_signing = usps_policies.branch("20");
	public static final ASN1ObjectIdentifier usps_medium_device = usps_policies.branch("37");
	public static final ASN1ObjectIdentifier usps_medium_device_hardware = usps_policies.branch("38");

	/*
	 * The following OIDs have been assigned to this agency as Test OIDs to mirror the above.
	 */
	public static final ASN1ObjectIdentifier usps_test = csor_certpolicy.branch("4");
	public static final ASN1ObjectIdentifier usps_test_rudimentary = usps_test.branch("1");
	public static final ASN1ObjectIdentifier usps_test_basic = usps_test.branch("2");
	public static final ASN1ObjectIdentifier usps_test_medium = usps_test.branch("3");
	public static final ASN1ObjectIdentifier usps_test_medium_hardware = usps_test.branch("12");
	public static final ASN1ObjectIdentifier usps_test_pivi_hardware = usps_test.branch("18");
	public static final ASN1ObjectIdentifier usps_test_pivi_cardauth = usps_test.branch("19");
	public static final ASN1ObjectIdentifier usps_test_pivi_content_signing = usps_test.branch("20");
	public static final ASN1ObjectIdentifier usps_test_medium_device = usps_test.branch("37");
	public static final ASN1ObjectIdentifier usps_test_medium_device_hardware = usps_test.branch("38");

	/*
	 * Committee On National Security Systems Registered Objects
	 * This arc is maintained by CNSS. The first object is an arc for the CNSS policies.
	 * 
	 * -- the CNSS policy arc
	 * id-cnss-policies OBJECT IDENTIFIER ::= { csor-certpolicy 21}
	 */
	public static final ASN1ObjectIdentifier cnss_policies = csor_certpolicy.branch("21");
	
	/*
	 * The OIDs assigned by this agency can be found in the Instruction for National Security Systems PKI X.509 Certificate Policy.
	 */

	/*
	 * Federal Energy Regulatory Commission Registered Objects
	 * Six objects have been registered to support the Federal Energy Regulatory Commission policies for PKI. The first object is an arc for the FERC policies.
	 * 
	 * -- the FERC policy arc
	 * id-ferc-policies OBJECT IDENTIFIER ::= { csor-certpolicy 22}
	 */
	public static final ASN1ObjectIdentifier ferc_policies = csor_certpolicy.branch("22");

	/*
	 * -- the ferc policy OIDS
	 * 
	 * These OIDs have been assigned to this agency; however, the Certificate Policy is not publicly available.
	 */
	public static final ASN1ObjectIdentifier ferc_test = ferc_policies.branch("1");
	public static final ASN1ObjectIdentifier ferc_basic = ferc_policies.branch("2");
	public static final ASN1ObjectIdentifier ferc_medium = ferc_policies.branch("3");
	public static final ASN1ObjectIdentifier ferc_medium_hardware = ferc_policies.branch("4");
	public static final ASN1ObjectIdentifier ferc_high = ferc_policies.branch("5");

	/*
	 * U.S. Agency For International Development
	 * Three objects have been registered to support the U.S. Agency for International Development policies for PKI. The first object is an arc for the USAID policies.
	 * 
	 * -- the USAID policy arc
	 * id-usaid-policies OBJECT IDENTIFIER ::= { csor-certpolicy 23}
	 */
	public static final ASN1ObjectIdentifier usaid_policies = csor_certpolicy.branch("23");

	/*
	 * -- the usaid policy OIDS
	 * 
	 * These OIDs have been assigned to this agency; however, the Certificate Policy is not publicly available.
	 */
	public static final ASN1ObjectIdentifier usaid_basic = usaid_policies.branch("23");
	public static final ASN1ObjectIdentifier usaid_medium = usaid_policies.branch("23");

	/*
	 * PKI Pilots And Testing Registered Objects
	 * There are 257 objects registered to support PKI pilots and testing. These objects define an arc for policies associated and 256 distinct policies. These policies should never be inserted in "real" certificates, and no relying party should ever accept such a certificate to implement security services in a "real" application! Note that the 256 policies are all equivalent and are defined within the "Test Certificate Policy to Support PKI Pilots and Testing" document.
	 * 
	 * -- test policy arc
	 * 
	 * csor-test-policies OBJECT IDENTIFIER ::= { 2 16 840 1 101 3 2 1 48 }
	 */
	public static final ASN1ObjectIdentifier csor_test = csor_certpolicy.branch("48");

	/*
	 * -- test policy OIDs
	 */
	public static final ASN1ObjectIdentifier csor_test1 = csor_test.branch("1");
	public static final ASN1ObjectIdentifier csor_test2 = csor_test.branch("2");
	public static final ASN1ObjectIdentifier csor_test3 = csor_test.branch("3");
	public static final ASN1ObjectIdentifier csor_test4 = csor_test.branch("4");
	public static final ASN1ObjectIdentifier csor_test5 = csor_test.branch("5");
	public static final ASN1ObjectIdentifier csor_test6 = csor_test.branch("6");
	public static final ASN1ObjectIdentifier csor_test7 = csor_test.branch("7");
	public static final ASN1ObjectIdentifier csor_test8 = csor_test.branch("8");
	public static final ASN1ObjectIdentifier csor_test9 = csor_test.branch("9");
	public static final ASN1ObjectIdentifier csor_test10 = csor_test.branch("10");
	public static final ASN1ObjectIdentifier csor_test11 = csor_test.branch("11");
	public static final ASN1ObjectIdentifier csor_test12 = csor_test.branch("12");
	public static final ASN1ObjectIdentifier csor_test13 = csor_test.branch("13");
	public static final ASN1ObjectIdentifier csor_test14 = csor_test.branch("14");
	public static final ASN1ObjectIdentifier csor_test15 = csor_test.branch("15");
	public static final ASN1ObjectIdentifier csor_test16 = csor_test.branch("16");
	public static final ASN1ObjectIdentifier csor_test17 = csor_test.branch("17");
	public static final ASN1ObjectIdentifier csor_test18 = csor_test.branch("18");
	public static final ASN1ObjectIdentifier csor_test19 = csor_test.branch("19");
	public static final ASN1ObjectIdentifier csor_test20 = csor_test.branch("20");
	public static final ASN1ObjectIdentifier csor_test21 = csor_test.branch("21");
	public static final ASN1ObjectIdentifier csor_test22 = csor_test.branch("22");
	public static final ASN1ObjectIdentifier csor_test23 = csor_test.branch("23");
	public static final ASN1ObjectIdentifier csor_test24 = csor_test.branch("24");
	public static final ASN1ObjectIdentifier csor_test25 = csor_test.branch("25");
	public static final ASN1ObjectIdentifier csor_test26 = csor_test.branch("26");
	public static final ASN1ObjectIdentifier csor_test27 = csor_test.branch("27");
	public static final ASN1ObjectIdentifier csor_test28 = csor_test.branch("28");
	public static final ASN1ObjectIdentifier csor_test29 = csor_test.branch("29");
	public static final ASN1ObjectIdentifier csor_test30 = csor_test.branch("30");
	public static final ASN1ObjectIdentifier csor_test31 = csor_test.branch("31");
	public static final ASN1ObjectIdentifier csor_test32 = csor_test.branch("32");
	public static final ASN1ObjectIdentifier csor_test33 = csor_test.branch("33");
	public static final ASN1ObjectIdentifier csor_test34 = csor_test.branch("34");
	public static final ASN1ObjectIdentifier csor_test35 = csor_test.branch("35");
	public static final ASN1ObjectIdentifier csor_test36 = csor_test.branch("36");
	public static final ASN1ObjectIdentifier csor_test37 = csor_test.branch("37");
	public static final ASN1ObjectIdentifier csor_test38 = csor_test.branch("38");
	public static final ASN1ObjectIdentifier csor_test39 = csor_test.branch("39");
	public static final ASN1ObjectIdentifier csor_test40 = csor_test.branch("40");
	public static final ASN1ObjectIdentifier csor_test41 = csor_test.branch("41");
	public static final ASN1ObjectIdentifier csor_test42 = csor_test.branch("42");
	public static final ASN1ObjectIdentifier csor_test43 = csor_test.branch("43");
	public static final ASN1ObjectIdentifier csor_test44 = csor_test.branch("44");
	public static final ASN1ObjectIdentifier csor_test45 = csor_test.branch("45");
	public static final ASN1ObjectIdentifier csor_test46 = csor_test.branch("46");
	public static final ASN1ObjectIdentifier csor_test47 = csor_test.branch("47");
	public static final ASN1ObjectIdentifier csor_test48 = csor_test.branch("48");
	public static final ASN1ObjectIdentifier csor_test49 = csor_test.branch("49");
	public static final ASN1ObjectIdentifier csor_test50 = csor_test.branch("50");
	public static final ASN1ObjectIdentifier csor_test51 = csor_test.branch("51");
	public static final ASN1ObjectIdentifier csor_test52 = csor_test.branch("52");
	public static final ASN1ObjectIdentifier csor_test53 = csor_test.branch("53");
	public static final ASN1ObjectIdentifier csor_test54 = csor_test.branch("54");
	public static final ASN1ObjectIdentifier csor_test55 = csor_test.branch("55");
	public static final ASN1ObjectIdentifier csor_test56 = csor_test.branch("56");
	public static final ASN1ObjectIdentifier csor_test57 = csor_test.branch("57");
	public static final ASN1ObjectIdentifier csor_test58 = csor_test.branch("58");
	public static final ASN1ObjectIdentifier csor_test59 = csor_test.branch("59");
	public static final ASN1ObjectIdentifier csor_test60 = csor_test.branch("60");
	public static final ASN1ObjectIdentifier csor_test61 = csor_test.branch("61");
	public static final ASN1ObjectIdentifier csor_test62 = csor_test.branch("62");
	public static final ASN1ObjectIdentifier csor_test63 = csor_test.branch("63");
	public static final ASN1ObjectIdentifier csor_test64 = csor_test.branch("64");
	public static final ASN1ObjectIdentifier csor_test65 = csor_test.branch("65");
	public static final ASN1ObjectIdentifier csor_test66 = csor_test.branch("66");
	public static final ASN1ObjectIdentifier csor_test67 = csor_test.branch("67");
	public static final ASN1ObjectIdentifier csor_test68 = csor_test.branch("68");
	public static final ASN1ObjectIdentifier csor_test69 = csor_test.branch("69");
	public static final ASN1ObjectIdentifier csor_test70 = csor_test.branch("70");
	public static final ASN1ObjectIdentifier csor_test71 = csor_test.branch("71");
	public static final ASN1ObjectIdentifier csor_test72 = csor_test.branch("72");
	public static final ASN1ObjectIdentifier csor_test73 = csor_test.branch("73");
	public static final ASN1ObjectIdentifier csor_test74 = csor_test.branch("74");
	public static final ASN1ObjectIdentifier csor_test75 = csor_test.branch("75");
	public static final ASN1ObjectIdentifier csor_test76 = csor_test.branch("76");
	public static final ASN1ObjectIdentifier csor_test77 = csor_test.branch("77");
	public static final ASN1ObjectIdentifier csor_test78 = csor_test.branch("78");
	public static final ASN1ObjectIdentifier csor_test79 = csor_test.branch("79");
	public static final ASN1ObjectIdentifier csor_test80 = csor_test.branch("80");
	public static final ASN1ObjectIdentifier csor_test81 = csor_test.branch("81");
	public static final ASN1ObjectIdentifier csor_test82 = csor_test.branch("82");
	public static final ASN1ObjectIdentifier csor_test83 = csor_test.branch("83");
	public static final ASN1ObjectIdentifier csor_test84 = csor_test.branch("84");
	public static final ASN1ObjectIdentifier csor_test85 = csor_test.branch("85");
	public static final ASN1ObjectIdentifier csor_test86 = csor_test.branch("86");
	public static final ASN1ObjectIdentifier csor_test87 = csor_test.branch("87");
	public static final ASN1ObjectIdentifier csor_test88 = csor_test.branch("88");
	public static final ASN1ObjectIdentifier csor_test89 = csor_test.branch("89");
	public static final ASN1ObjectIdentifier csor_test90 = csor_test.branch("90");
	public static final ASN1ObjectIdentifier csor_test91 = csor_test.branch("91");
	public static final ASN1ObjectIdentifier csor_test92 = csor_test.branch("92");
	public static final ASN1ObjectIdentifier csor_test93 = csor_test.branch("93");
	public static final ASN1ObjectIdentifier csor_test94 = csor_test.branch("94");
	public static final ASN1ObjectIdentifier csor_test95 = csor_test.branch("95");
	public static final ASN1ObjectIdentifier csor_test96 = csor_test.branch("96");
	public static final ASN1ObjectIdentifier csor_test97 = csor_test.branch("97");
	public static final ASN1ObjectIdentifier csor_test98 = csor_test.branch("98");
	public static final ASN1ObjectIdentifier csor_test99 = csor_test.branch("99");
	public static final ASN1ObjectIdentifier csor_test100 = csor_test.branch("100");
	public static final ASN1ObjectIdentifier csor_test101 = csor_test.branch("101");
	public static final ASN1ObjectIdentifier csor_test102 = csor_test.branch("102");
	public static final ASN1ObjectIdentifier csor_test103 = csor_test.branch("103");
	public static final ASN1ObjectIdentifier csor_test104 = csor_test.branch("104");
	public static final ASN1ObjectIdentifier csor_test105 = csor_test.branch("105");
	public static final ASN1ObjectIdentifier csor_test106 = csor_test.branch("106");
	public static final ASN1ObjectIdentifier csor_test107 = csor_test.branch("107");
	public static final ASN1ObjectIdentifier csor_test108 = csor_test.branch("108");
	public static final ASN1ObjectIdentifier csor_test109 = csor_test.branch("109");
	public static final ASN1ObjectIdentifier csor_test110 = csor_test.branch("110");
	public static final ASN1ObjectIdentifier csor_test111 = csor_test.branch("111");
	public static final ASN1ObjectIdentifier csor_test112 = csor_test.branch("112");
	public static final ASN1ObjectIdentifier csor_test113 = csor_test.branch("113");
	public static final ASN1ObjectIdentifier csor_test114 = csor_test.branch("114");
	public static final ASN1ObjectIdentifier csor_test115 = csor_test.branch("115");
	public static final ASN1ObjectIdentifier csor_test116 = csor_test.branch("116");
	public static final ASN1ObjectIdentifier csor_test117 = csor_test.branch("117");
	public static final ASN1ObjectIdentifier csor_test118 = csor_test.branch("118");
	public static final ASN1ObjectIdentifier csor_test119 = csor_test.branch("119");
	public static final ASN1ObjectIdentifier csor_test120 = csor_test.branch("120");
	public static final ASN1ObjectIdentifier csor_test121 = csor_test.branch("121");
	public static final ASN1ObjectIdentifier csor_test122 = csor_test.branch("122");
	public static final ASN1ObjectIdentifier csor_test123 = csor_test.branch("123");
	public static final ASN1ObjectIdentifier csor_test124 = csor_test.branch("124");
	public static final ASN1ObjectIdentifier csor_test125 = csor_test.branch("125");
	public static final ASN1ObjectIdentifier csor_test126 = csor_test.branch("126");
	public static final ASN1ObjectIdentifier csor_test127 = csor_test.branch("127");
	public static final ASN1ObjectIdentifier csor_test128 = csor_test.branch("128");
	public static final ASN1ObjectIdentifier csor_test129 = csor_test.branch("129");
	public static final ASN1ObjectIdentifier csor_test130 = csor_test.branch("130");
	public static final ASN1ObjectIdentifier csor_test131 = csor_test.branch("131");
	public static final ASN1ObjectIdentifier csor_test132 = csor_test.branch("132");
	public static final ASN1ObjectIdentifier csor_test133 = csor_test.branch("133");
	public static final ASN1ObjectIdentifier csor_test134 = csor_test.branch("134");
	public static final ASN1ObjectIdentifier csor_test135 = csor_test.branch("135");
	public static final ASN1ObjectIdentifier csor_test136 = csor_test.branch("136");
	public static final ASN1ObjectIdentifier csor_test137 = csor_test.branch("137");
	public static final ASN1ObjectIdentifier csor_test138 = csor_test.branch("138");
	public static final ASN1ObjectIdentifier csor_test139 = csor_test.branch("139");
	public static final ASN1ObjectIdentifier csor_test140 = csor_test.branch("140");
	public static final ASN1ObjectIdentifier csor_test141 = csor_test.branch("141");
	public static final ASN1ObjectIdentifier csor_test142 = csor_test.branch("142");
	public static final ASN1ObjectIdentifier csor_test143 = csor_test.branch("143");
	public static final ASN1ObjectIdentifier csor_test144 = csor_test.branch("144");
	public static final ASN1ObjectIdentifier csor_test145 = csor_test.branch("145");
	public static final ASN1ObjectIdentifier csor_test146 = csor_test.branch("146");
	public static final ASN1ObjectIdentifier csor_test147 = csor_test.branch("147");
	public static final ASN1ObjectIdentifier csor_test148 = csor_test.branch("148");
	public static final ASN1ObjectIdentifier csor_test149 = csor_test.branch("149");
	public static final ASN1ObjectIdentifier csor_test150 = csor_test.branch("150");
	public static final ASN1ObjectIdentifier csor_test151 = csor_test.branch("151");
	public static final ASN1ObjectIdentifier csor_test152 = csor_test.branch("152");
	public static final ASN1ObjectIdentifier csor_test153 = csor_test.branch("153");
	public static final ASN1ObjectIdentifier csor_test154 = csor_test.branch("154");
	public static final ASN1ObjectIdentifier csor_test155 = csor_test.branch("155");
	public static final ASN1ObjectIdentifier csor_test156 = csor_test.branch("156");
	public static final ASN1ObjectIdentifier csor_test157 = csor_test.branch("157");
	public static final ASN1ObjectIdentifier csor_test158 = csor_test.branch("158");
	public static final ASN1ObjectIdentifier csor_test159 = csor_test.branch("159");
	public static final ASN1ObjectIdentifier csor_test160 = csor_test.branch("160");
	public static final ASN1ObjectIdentifier csor_test161 = csor_test.branch("161");
	public static final ASN1ObjectIdentifier csor_test162 = csor_test.branch("162");
	public static final ASN1ObjectIdentifier csor_test163 = csor_test.branch("163");
	public static final ASN1ObjectIdentifier csor_test164 = csor_test.branch("164");
	public static final ASN1ObjectIdentifier csor_test165 = csor_test.branch("165");
	public static final ASN1ObjectIdentifier csor_test166 = csor_test.branch("166");
	public static final ASN1ObjectIdentifier csor_test167 = csor_test.branch("167");
	public static final ASN1ObjectIdentifier csor_test168 = csor_test.branch("168");
	public static final ASN1ObjectIdentifier csor_test169 = csor_test.branch("169");
	public static final ASN1ObjectIdentifier csor_test170 = csor_test.branch("170");
	public static final ASN1ObjectIdentifier csor_test171 = csor_test.branch("171");
	public static final ASN1ObjectIdentifier csor_test172 = csor_test.branch("172");
	public static final ASN1ObjectIdentifier csor_test173 = csor_test.branch("173");
	public static final ASN1ObjectIdentifier csor_test174 = csor_test.branch("174");
	public static final ASN1ObjectIdentifier csor_test175 = csor_test.branch("175");
	public static final ASN1ObjectIdentifier csor_test176 = csor_test.branch("176");
	public static final ASN1ObjectIdentifier csor_test177 = csor_test.branch("177");
	public static final ASN1ObjectIdentifier csor_test178 = csor_test.branch("178");
	public static final ASN1ObjectIdentifier csor_test179 = csor_test.branch("179");
	public static final ASN1ObjectIdentifier csor_test180 = csor_test.branch("180");
	public static final ASN1ObjectIdentifier csor_test181 = csor_test.branch("181");
	public static final ASN1ObjectIdentifier csor_test182 = csor_test.branch("182");
	public static final ASN1ObjectIdentifier csor_test183 = csor_test.branch("183");
	public static final ASN1ObjectIdentifier csor_test184 = csor_test.branch("184");
	public static final ASN1ObjectIdentifier csor_test185 = csor_test.branch("185");
	public static final ASN1ObjectIdentifier csor_test186 = csor_test.branch("186");
	public static final ASN1ObjectIdentifier csor_test187 = csor_test.branch("187");
	public static final ASN1ObjectIdentifier csor_test188 = csor_test.branch("188");
	public static final ASN1ObjectIdentifier csor_test189 = csor_test.branch("189");
	public static final ASN1ObjectIdentifier csor_test190 = csor_test.branch("190");
	public static final ASN1ObjectIdentifier csor_test191 = csor_test.branch("191");
	public static final ASN1ObjectIdentifier csor_test192 = csor_test.branch("192");
	public static final ASN1ObjectIdentifier csor_test193 = csor_test.branch("193");
	public static final ASN1ObjectIdentifier csor_test194 = csor_test.branch("194");
	public static final ASN1ObjectIdentifier csor_test195 = csor_test.branch("195");
	public static final ASN1ObjectIdentifier csor_test196 = csor_test.branch("196");
	public static final ASN1ObjectIdentifier csor_test197 = csor_test.branch("197");
	public static final ASN1ObjectIdentifier csor_test198 = csor_test.branch("198");
	public static final ASN1ObjectIdentifier csor_test199 = csor_test.branch("199");
	public static final ASN1ObjectIdentifier csor_test200 = csor_test.branch("200");
	public static final ASN1ObjectIdentifier csor_test201 = csor_test.branch("201");
	public static final ASN1ObjectIdentifier csor_test202 = csor_test.branch("202");
	public static final ASN1ObjectIdentifier csor_test203 = csor_test.branch("203");
	public static final ASN1ObjectIdentifier csor_test204 = csor_test.branch("204");
	public static final ASN1ObjectIdentifier csor_test205 = csor_test.branch("205");
	public static final ASN1ObjectIdentifier csor_test206 = csor_test.branch("206");
	public static final ASN1ObjectIdentifier csor_test207 = csor_test.branch("207");
	public static final ASN1ObjectIdentifier csor_test208 = csor_test.branch("208");
	public static final ASN1ObjectIdentifier csor_test209 = csor_test.branch("209");
	public static final ASN1ObjectIdentifier csor_test210 = csor_test.branch("210");
	public static final ASN1ObjectIdentifier csor_test211 = csor_test.branch("211");
	public static final ASN1ObjectIdentifier csor_test212 = csor_test.branch("212");
	public static final ASN1ObjectIdentifier csor_test213 = csor_test.branch("213");
	public static final ASN1ObjectIdentifier csor_test214 = csor_test.branch("214");
	public static final ASN1ObjectIdentifier csor_test215 = csor_test.branch("215");
	public static final ASN1ObjectIdentifier csor_test216 = csor_test.branch("216");
	public static final ASN1ObjectIdentifier csor_test217 = csor_test.branch("217");
	public static final ASN1ObjectIdentifier csor_test218 = csor_test.branch("218");
	public static final ASN1ObjectIdentifier csor_test219 = csor_test.branch("219");
	public static final ASN1ObjectIdentifier csor_test220 = csor_test.branch("220");
	public static final ASN1ObjectIdentifier csor_test221 = csor_test.branch("221");
	public static final ASN1ObjectIdentifier csor_test222 = csor_test.branch("222");
	public static final ASN1ObjectIdentifier csor_test223 = csor_test.branch("223");
	public static final ASN1ObjectIdentifier csor_test224 = csor_test.branch("224");
	public static final ASN1ObjectIdentifier csor_test225 = csor_test.branch("225");
	public static final ASN1ObjectIdentifier csor_test226 = csor_test.branch("226");
	public static final ASN1ObjectIdentifier csor_test227 = csor_test.branch("227");
	public static final ASN1ObjectIdentifier csor_test228 = csor_test.branch("228");
	public static final ASN1ObjectIdentifier csor_test229 = csor_test.branch("229");
	public static final ASN1ObjectIdentifier csor_test230 = csor_test.branch("230");
	public static final ASN1ObjectIdentifier csor_test231 = csor_test.branch("231");
	public static final ASN1ObjectIdentifier csor_test232 = csor_test.branch("232");
	public static final ASN1ObjectIdentifier csor_test233 = csor_test.branch("233");
	public static final ASN1ObjectIdentifier csor_test234 = csor_test.branch("234");
	public static final ASN1ObjectIdentifier csor_test235 = csor_test.branch("235");
	public static final ASN1ObjectIdentifier csor_test236 = csor_test.branch("236");
	public static final ASN1ObjectIdentifier csor_test237 = csor_test.branch("237");
	public static final ASN1ObjectIdentifier csor_test238 = csor_test.branch("238");
	public static final ASN1ObjectIdentifier csor_test239 = csor_test.branch("239");
	public static final ASN1ObjectIdentifier csor_test240 = csor_test.branch("240");
	public static final ASN1ObjectIdentifier csor_test241 = csor_test.branch("241");
	public static final ASN1ObjectIdentifier csor_test242 = csor_test.branch("242");
	public static final ASN1ObjectIdentifier csor_test243 = csor_test.branch("243");
	public static final ASN1ObjectIdentifier csor_test244 = csor_test.branch("244");
	public static final ASN1ObjectIdentifier csor_test245 = csor_test.branch("245");
	public static final ASN1ObjectIdentifier csor_test246 = csor_test.branch("246");
	public static final ASN1ObjectIdentifier csor_test247 = csor_test.branch("247");
	public static final ASN1ObjectIdentifier csor_test248 = csor_test.branch("248");
	public static final ASN1ObjectIdentifier csor_test249 = csor_test.branch("249");
	public static final ASN1ObjectIdentifier csor_test250 = csor_test.branch("250");
	public static final ASN1ObjectIdentifier csor_test251 = csor_test.branch("251");
	public static final ASN1ObjectIdentifier csor_test252 = csor_test.branch("252");
	public static final ASN1ObjectIdentifier csor_test253 = csor_test.branch("253");
	public static final ASN1ObjectIdentifier csor_test254 = csor_test.branch("254");
	public static final ASN1ObjectIdentifier csor_test255 = csor_test.branch("255");
	public static final ASN1ObjectIdentifier csor_test256 = csor_test.branch("256");	

}
