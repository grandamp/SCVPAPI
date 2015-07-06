package org.keysupport.bc.scvp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.keysupport.bc.scvp.asn1.CertChecks;
import org.keysupport.bc.scvp.asn1.SCVPRequest;
import org.keysupport.crypto.CipherEngine;
import org.keysupport.crypto.DigestEngine;
import org.keysupport.util.DataUtil;

public class ExampleSCVPClient {

	public ExampleSCVPClient() {
		// TODO Auto-generated constructor stub
	}

	/*
	 * Temporary main method for testing.
	 */
	public static void main(String args[]) throws SCVPException {

		/*
		 * The intent is to change the provider for the cryptographic
		 * operations. I.e., a FIPS provider if needed. For now, we will use the
		 * BouncyCastle API since that is what we use for the ASN.1
		 */
		Provider jceProvider = new BouncyCastleProvider();
		Security.addProvider(jceProvider);

		long start = System.currentTimeMillis();
		CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509", jceProvider.getName());
		} catch (NoSuchProviderException e) {
			throw new SCVPException("Problem with JCE Provider", e);
		} catch (CertificateException e) {
			throw new SCVPException("Problem with JCE Provider", e);
		}
		String certFile = "/tmp/eeCert";
		X509Certificate endEntityCert;
		ByteArrayInputStream bais;
		Certificate eCert;
		try {
			endEntityCert = (X509Certificate) cf
					.generateCertificate(new FileInputStream(certFile));
			bais = new ByteArrayInputStream(endEntityCert.getEncoded());
			ASN1InputStream dis = new ASN1InputStream(bais);
			ASN1Primitive dobj = dis.readObject();
			dis.close();
			eCert = Certificate.getInstance(dobj);
		} catch (FileNotFoundException e) {
			throw new SCVPException("Problem with client certificate", e);
		} catch (IOException e) {
			throw new SCVPException("Problem with client certificate", e);
		} catch (CertificateException e) {
			throw new SCVPException("Problem with client certificate", e);
		}
		System.out.println("Client Cert Subject:\t"
				+ eCert.getSubject().toString());

		SCVPRequestBuilder builder = new SCVPRequestBuilder();
		/*
		 * We are forming a delegated path validation request, and we are not
		 * going to ask for any wantBack(s). We are basically trusting the SCVP
		 * service to centrally validate our certificates.
		 */
		builder.addCertCheck(CertChecks.idStcBuildStatusCheckedPkcPath);
		/*
		 * We can override policy, but our SCVP testing service makes use of the
		 * Common Policy Root CA as the Trust Anchor.
		 */
		// builder.addTrustAnchors(trustAnchor);
		builder.setValidationPolRef(new ASN1ObjectIdentifier(
				"1.3.6.1.5.5.7.19.1"), null);
		/*
		 * Adding policy OIDs for OMB M-04-04 LOA-4:
		 * 
		 * http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-2.
		 * pdf#page=123
		 * 
		 * Where the OIDs are documented at:
		 * 
		 * http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/pki_registration
		 * .html
		 */
		builder.addUserPolicy(new ASN1ObjectIdentifier(
				"2.16.840.1.101.3.2.1.3.13")); // Common-Auth
		builder.addUserPolicy(new ASN1ObjectIdentifier(
				"2.16.840.1.101.3.2.1.3.18")); // PIVI-Auth
		builder.addUserPolicy(new ASN1ObjectIdentifier(
				"2.16.840.1.101.3.2.1.3.26")); // SHA1-Auth
		builder.addUserPolicy(new ASN1ObjectIdentifier(
				"2.16.840.1.101.3.2.1.3.7")); // Common-HW
		builder.addUserPolicy(new ASN1ObjectIdentifier(
				"2.16.840.1.101.3.2.1.3.18")); // PIVI-HW
		builder.addUserPolicy(new ASN1ObjectIdentifier(
				"2.16.840.1.101.3.2.1.3.24")); // SHA1-HW
		builder.addUserPolicy(new ASN1ObjectIdentifier(
				"2.16.840.1.101.3.2.1.3.16")); // Common-High
		builder.addUserPolicy(new ASN1ObjectIdentifier(
				"2.16.840.1.101.3.2.1.3.12")); // FBCA Medium-HW
		builder.addUserPolicy(new ASN1ObjectIdentifier(
				"2.16.840.1.101.3.2.1.3.4")); // FBCA High
		/*
		 * These are the additional RFC-5280 inputs:
		 * 
		 * We do not allow wild-card policy assertions (InhibitAnyPolicy). We
		 * require the policy oids to be present in all certs within the path
		 * (RequireExplicitPolicy). We allow mapped policies in place of the
		 * explicitly defined inital policy set.
		 */
		builder.setInhibitAnyPolicy(true);
		builder.setRequireExplicitPolicy(true);
		builder.setInhibitPolicyMapping(false);
		/*
		 * This is the certificate we are validating
		 */
		builder.addCertReference(eCert);
		/*
		 * This is based off of the GSA SCVP Request/Response Profile
		 */
		builder.setRequestorName("URN:ValidationService:TEST:SCVPExample");
		builder.setRequestorText("LOG;HI;MAJ;OTH;APP,HTTP://FOO.GOV/,-");
		/*
		 * Adding a 16 byte nonce
		 */
		builder.generateNonce(16);
		/*
		 * Final assembly of the request.
		 */
		SCVPRequest req = builder.buildRequest();
		byte[] rawReq;
		try {
			rawReq = req.toASN1Primitive().getEncoded();
		} catch (IOException e) {
			throw new SCVPException("Problem with SCVP Request", e);
		}
		/*
		 * Send the request to the SCVP service...
		 */
		byte[] resp = sendSCVPRequestPOST("https://foo.com/", rawReq);

		/*
		 * Now that we ca create a successful DPV request and receive a response
		 * from the service, we had better get to cracking on parsing the
		 * response and validating the signature!
		 */
		ASN1SequenceParser cmsSeqPar = null;
		ContentInfoParser contentInfoParser = null;
		ASN1ObjectIdentifier contentType = null;
		if (resp != null) {
			ASN1StreamParser streamParser = new ASN1StreamParser(resp);
			Object object;
			try {
				object = streamParser.readObject();
			} catch (IOException e) {
				throw new SCVPException("Problem parsing response from server",
						e);
			}
			if (object instanceof ASN1SequenceParser) {
				cmsSeqPar = (ASN1SequenceParser) object;
				try {
					contentInfoParser = new ContentInfoParser(cmsSeqPar);
				} catch (IOException e) {
					throw new SCVPException("Problem parsing CMS ContentInfo",
							e);
				}
				contentType = contentInfoParser.getContentType();
				if (CMSObjectIdentifiers.signedData.equals(contentType)) {
					System.out.println("CMS Content Type:\t"
							+ contentType.toString());
					// If we are here, then this is a CMS Signed Data object
					try {
						object = streamParser.readObject();
					} catch (IOException e) {
						throw new SCVPException(
								"Problem parsing response from server", e);
					}
					if (object instanceof ASN1SequenceParser) {
						/*
						 * Now that we confirmed this is CMS Signed data we are
						 * going to start parsing what we know without checking
						 * (not a good long term solution)
						 */
						ASN1SequenceParser cmsSdPar = (ASN1SequenceParser) object;
						// version CMSVersion
						ASN1Integer sdv;
						try {
							sdv = (ASN1Integer) cmsSdPar.readObject();
						} catch (IOException e) {
							throw new SCVPException(
									"Problem parsing CMS Version", e);
						}
						System.out.println("SignedData Version:\t"
								+ sdv.toString());
						// digestAlgorithms DigestAlgorithmIdentifiers
						ASN1SetParser dASetPar;
						AlgorithmIdentifier algId;
						try {
							dASetPar = (ASN1SetParser) cmsSdPar.readObject();
							algId = AlgorithmIdentifier.getInstance(dASetPar
									.readObject());
						} catch (IOException e) {
							throw new SCVPException(
									"Problem parsing digest algorithm identifier",
									e);
						}
						System.out.println("Digest Algorithm:\t"
								+ algId.getAlgorithm().toString());
						// encapContentInfo EncapsulatedContentInfo
						ASN1SequenceParser eCInfoPar;
						ASN1ObjectIdentifier eContentType;
						ASN1TaggedObjectParser eContent;
						ASN1OctetString cVResponse;
						try {
							eCInfoPar = (ASN1SequenceParser) cmsSdPar
									.readObject();
							eContentType = (ASN1ObjectIdentifier) eCInfoPar
									.readObject();
							System.out.println("Encap Cont Type:\t"
									+ eContentType.toString());
							eContent = (ASN1TaggedObjectParser) eCInfoPar
									.readObject();
							cVResponse = (ASN1OctetString) eContent
									.getObjectParser(0, true).toASN1Primitive();
						} catch (IOException e) {
							throw new SCVPException(
									"Problem parsing EncapsulatedContentInfo",
									e);
						}
						/*
						 * Digest the object bytes for signature validation
						 */
						byte[] cVRespBytes = cVResponse.getOctets();
						byte[] digest = null;
						/*
						 * Only support SHA-1/SHA-256/SHA-384. Die on validation
						 * otherwise.
						 */
						if (algId.getAlgorithm().equals(CipherEngine.SHA384)) {
							/*
							 * SHA-384
							 */
							digest = DigestEngine.sHA384Sum(cVRespBytes,
									jceProvider.getName());
						} else if (algId.getAlgorithm().equals(
								CipherEngine.SHA256)) {
							/*
							 * SHA-256
							 */
							digest = DigestEngine.sHA256Sum(cVRespBytes,
									jceProvider.getName());
						} else if (algId.getAlgorithm().equals(
								CipherEngine.SHA1)) {
							/*
							 * SHA-1
							 */
							digest = DigestEngine.sHA1Sum(cVRespBytes,
									jceProvider.getName());
						} else {
							throw new SCVPException(
									"Unexpected Digest Algorithm: "
											+ algId.getAlgorithm().getId());
						}
						System.out.println("CVResponse Digest:\t"
								+ DataUtil.byteArrayToString(digest));
						// certificates [0] IMPLICIT CertificateSet OPTIONAL
						ASN1TaggedObjectParser certSet;
						Certificate cvSigner;
						try {
							certSet = (ASN1TaggedObjectParser) cmsSdPar
									.readObject();
							cvSigner = Certificate
									.getInstance(certSet.getObjectParser(0,
											true).toASN1Primitive());
						} catch (IOException e) {
							throw new SCVPException(
									"Error parsing SCVP Signer in CMS", e);
						}
						System.out.println("Signer Subject:\t\t"
								+ cvSigner.getSubject().toString());
						// SignerInfos ::= SET OF SignerInfo
						ASN1SetParser sInfosPar;
						SignerInfo sInfo;
						try {
							sInfosPar = (ASN1SetParser) cmsSdPar.readObject();
							sInfo = SignerInfo.getInstance(sInfosPar
									.readObject().toASN1Primitive());
						} catch (IOException e) {
							throw new SCVPException("Error parsing SignerInfo",
									e);
						}
						SignerIdentifier sID = sInfo.getSID();
						IssuerAndSerialNumber iSn = IssuerAndSerialNumber
								.getInstance(sID);
						if (iSn.equals(new IssuerAndSerialNumber(cvSigner))) {
							/*
							 * To get here the signerInfo references the
							 * included signer and we will proceed to parse the
							 * SignerInfo, which includes the digest of (and
							 * reference to) a CVResponse, and the encrypted
							 * value (signature). Parse and validate the
							 * signature...
							 */
							System.out.println("Cert matches SI:\tTRUE");
							AlgorithmIdentifier sIAlgId = sInfo
									.getDigestAlgorithm();
							System.out.println("SI Digest Algorithm:\t"
									+ sIAlgId.getAlgorithm().toString());
							Attributes sIAA = Attributes.getInstance(sInfo
									.getAuthenticatedAttributes());
							Attribute siContentType = null;
							Attribute siSigningTime = null;
							Attribute siMessageDigest = null;
							for (Attribute a : sIAA.getAttributes()) {
								if (a.getAttrType().equals(
										new ASN1ObjectIdentifier(
												"1.2.840.113549.1.9.3"))) {
									siContentType = a;
								}
								if (a.getAttrType().equals(
										new ASN1ObjectIdentifier(
												"1.2.840.113549.1.9.5"))) {
									siSigningTime = a;
								}
								if (a.getAttrType().equals(
										new ASN1ObjectIdentifier(
												"1.2.840.113549.1.9.4"))) {
									siMessageDigest = a;
								}
							}
							/*
							 * Make sure the SignerInfo has all that we expect,
							 * and lets validate the data.
							 * 
							 * -ContentType: Make sure it is an SCVP Response
							 * -SigningTime: We use a nonce, ensure it was
							 * signed within the past minute -MessageDigest:
							 * This must match the digest of the CVResponse
							 */
							if (siContentType != null && siSigningTime != null
									&& siMessageDigest != null) {
								ASN1ObjectIdentifier siCT = (ASN1ObjectIdentifier) siContentType
										.getAttrValues().getObjectAt(0);
								if (siCT.equals(new ASN1ObjectIdentifier(
										"1.2.840.113549.1.9.16.1.11"))) {
									System.out
											.println("SignerInfo ContentType:\tid-ct-scvp-psResponse");
								} else {
									throw new SCVPException(
											"Unexpected Content Type: "
													+ siCT.getId());
								}
								Calendar currentTime = Calendar.getInstance();
								ASN1UTCTime claimSignTime = (ASN1UTCTime) siSigningTime
										.getAttrValues().getObjectAt(0);
								Calendar signingTime = new GregorianCalendar();
								try {
									signingTime.setTime(claimSignTime
											.getAdjustedDate());
								} catch (ParseException e) {
									throw new SCVPException(
											"Error parsing SigningTime", e);
								}
								System.out.println("Current Time:\t\t"
										+ currentTime.getTime().toString());
								System.out.println("Signing Time:\t\t"
										+ signingTime.getTime().toString());
								Calendar minBefore = new GregorianCalendar();
								Calendar minAfter = new GregorianCalendar();
								minBefore.add(Calendar.MINUTE, -1);
								minAfter.add(Calendar.MINUTE, 1);
								System.out.println("Minute Before:\t\t"
										+ minBefore.getTime().toString());
								System.out.println("Minute After:\t\t"
										+ minAfter.getTime().toString());
								if (!(currentTime.before(minBefore) || currentTime
										.after(minAfter))) {
									System.out
											.println("Signing Timeframe:\tAcceptable");
								} else {
									throw new SCVPException(
											"Unacceptable Signing Time: "
													+ claimSignTime
															.getAdjustedTime());
								}
								ASN1OctetString claimDigestOS = (ASN1OctetString) siMessageDigest
										.getAttrValues().getObjectAt(0);
								byte[] claimDigest = claimDigestOS.getOctets();
								System.out
										.println("Claimed Digest:\t\t"
												+ DataUtil
														.byteArrayToString(claimDigest));
								if (Arrays.areEqual(digest, claimDigest)) {
									System.out
											.println("Calc and Claim Digest:\tMatch");
								} else {
									throw new SCVPException(
											"SignerInfo Message Digest ("
													+ DataUtil
															.byteArrayToString(claimDigest)
													+ ") does is not equal to actual digest ("
													+ DataUtil
															.byteArrayToString(digest)
													+ ")");
								}
							} else {
								throw new SCVPException(
										"SignerInfo does not include requred Authenticated attributes");
							}
							AlgorithmIdentifier sigAlg = sInfo
									.getDigestEncryptionAlgorithm();
							byte[] sigBits = sInfo.getEncryptedDigest()
									.getOctets();
							String sigAlgName = CipherEngine
									.getSigningAlgorithm(
											sIAlgId.getAlgorithm(),
											sigAlg.getAlgorithm());
							System.out.println("Signature Algorithm:\t"
									+ sigAlgName);
							System.out.println("Sig Length (bits):\t"
									+ sigBits.length * Byte.SIZE);
							Signature signature = null;
							try {
								signature = Signature.getInstance(sigAlgName,
										jceProvider.getName());
							} catch (NoSuchAlgorithmException
									| NoSuchProviderException e) {
								throw new SCVPException(
										"Problem verifing signature", e);
							}
							InputStream in;
							try {
								in = new ByteArrayInputStream(
										cvSigner.getEncoded());
							} catch (IOException e) {
								throw new SCVPException(
										"Error parsing SCVP Signer Certificate",
										e);
							}
							X509Certificate cvSignerCert;
							try {
								cvSignerCert = (X509Certificate) cf
										.generateCertificate(in);
								signature.initVerify(cvSignerCert);
							} catch (InvalidKeyException e) {
								throw new SCVPException(
										"Problem parsing SCVP Signer public key",
										e);
							} catch (CertificateException e) {
								throw new SCVPException(
										"Problem parsing SCVP Signing certificate",
										e);
							}
							try {
								signature.update(sIAA.getEncoded());
							} catch (SignatureException | IOException e) {
								throw new SCVPException(
										"Problem with SCVP Signature validation",
										e);
							}
							boolean sigMatch = false;
							try {
								sigMatch = signature.verify(sigBits);
							} catch (SignatureException e) {
								throw new SCVPException(
										"Invalid SCVP Signature: Signature Validation Failed",
										e);
							}
							if (sigMatch) {
								System.out.println("Signature Valid:\tTRUE");
								/*
								 * TODO: Validate that we trust the SCVP Signer
								 * certificate
								 * 
								 * Now we will process the CVResponse, verify
								 * the response from the request artifacts, and
								 * then return a result for human (or other IT
								 * Logic) consumption. We will render the
								 * CVResponse from the response bytes we
								 * digested (used for signature validation).
								 */
								System.out
										.println("CVResponse Bytes:\t"
												+ DataUtil
														.byteArrayToString(cVRespBytes));
								ASN1StreamParser cvRespOs = new ASN1StreamParser(
										cVRespBytes);
								ASN1SequenceParser cvResp;
								ASN1Integer cvResponseVersion;
								ASN1Integer serverConfigurationID;
								ASN1GeneralizedTime producedAt;
								ASN1Sequence responseStatus;

								ASN1Sequence respValidationPolicy = null;
								ASN1TaggedObject requestRef = null;
								ASN1Sequence requestorRef = null;
								ASN1Sequence requestorName = null;
								ASN1Sequence replyObjects = null;
								ASN1OctetString respNonce = null;
								ASN1OctetString serverContextInfo = null;
								ASN1Sequence cvResponseExtensions = null;
								ASN1OctetString requestorText = null;
								try {
									cvResp = (ASN1SequenceParser) cvRespOs
											.readObject();
									cvResponseVersion = ASN1Integer
											.getInstance(cvResp.readObject());
									System.out.println("CVResponse Version:\t"
											+ cvResponseVersion.getValue()
													.toString());
									serverConfigurationID = ASN1Integer
											.getInstance(cvResp.readObject());
									System.out
											.println("CVResponse server Conf:\t"
													+ serverConfigurationID
															.getValue()
															.toString());
									producedAt = ASN1GeneralizedTime
											.getInstance(cvResp.readObject());
									System.out
											.println("CVResponse producedAt:\t"
													+ producedAt
															.getTimeString());
									responseStatus = ASN1Sequence
											.getInstance(cvResp.readObject());
									ASN1Enumerated statusCode = ASN1Enumerated
											.getInstance(responseStatus
													.getObjectAt(0));
									System.out.println("CVResponse Status:\t"
											+ statusCode.getValue().toString());
									/*
									 * The remainder objects in this CVResponse
									 * are tagged and OPTIONAL.
									 */
									Object cvrObj;
									while ((cvrObj = cvResp.readObject()) != null) {
										ASN1TaggedObject atObjFp = (ASN1TaggedObject) ((ASN1TaggedObjectParser) cvrObj)
												.toASN1Primitive();
										switch (atObjFp.getTagNo()) {
										case 0: {
											respValidationPolicy = (ASN1Sequence) atObjFp
													.getObject();
											System.out
													.println("[0]respValidationPolicy:"
															+ DataUtil
																	.byteArrayToString(respValidationPolicy
																			.getEncoded()));
											break;
										}
										case 1: {
											requestRef = (ASN1TaggedObject) atObjFp
													.getObject();
											System.out
													.println("[1]requestRef:\t\t"
															+ DataUtil
																	.byteArrayToString(requestRef
																			.getEncoded()));
											break;
										}
										case 2: {
											requestorRef = (ASN1Sequence) atObjFp
													.getObject();
											System.out
													.println("[2]requestorRef:\t"
															+ DataUtil
																	.byteArrayToString(requestorRef
																			.getEncoded()));
											break;
										}
										case 3: {
											requestorName = (ASN1Sequence) atObjFp
													.getObject();
											System.out
													.println("[3]requestorName:\t"
															+ DataUtil
																	.byteArrayToString(requestorName
																			.getEncoded()));
											break;
										}
										case 4: {
											replyObjects = (ASN1Sequence) atObjFp
													.getObject();
											System.out
													.println("[4]replyObjects:\t"
															+ DataUtil
																	.byteArrayToString(replyObjects
																			.getEncoded()));
											break;
										}
										case 5: {
											respNonce = (ASN1OctetString) atObjFp
													.getObject();
											System.out
													.println("[5]respNonce:\t\t"
															+ DataUtil
																	.byteArrayToString(respNonce
																			.getEncoded()));
											break;
										}
										case 6: {
											serverContextInfo = (ASN1OctetString) atObjFp
													.getObject();
											System.out
													.println("[6]serverContextInfo:\t"
															+ DataUtil
																	.byteArrayToString(serverContextInfo
																			.getEncoded()));
											break;
										}
										case 7: {
											cvResponseExtensions = (ASN1Sequence) atObjFp
													.getObject();
											System.out
													.println("[7]cvResponseExtensions:\t"
															+ DataUtil
																	.byteArrayToString(cvResponseExtensions
																			.getEncoded()));
											break;
										}
										case 8: {
											requestorText = (ASN1OctetString) atObjFp
													.getObject();
											System.out
													.println("[8]requestorText:\t"
															+ DataUtil
																	.byteArrayToString(requestorText
																			.getEncoded()));
											break;
										}
										default: {
											throw new SCVPException(
													"Unknown object encountered in CVResponse");
										}
										}
									}
								} catch (IOException e) {
									throw new SCVPException(
											"Error parsing CVResponse", e);
								}
								/*
								 * TODO: Decode the other objects, and match up
								 * to the request response objects to validate
								 * the response. I.e., requestRef, respNonce,
								 * etc...
								 * 
								 * For now, we are only interested in the
								 * replyObjects to give us the certificate
								 * status. There is only one, because we only
								 * asked for one.
								 */
								if (replyObjects != null) {
									/*
									 * Technically we have the single
									 * replyObject, so the following is the
									 * results of our hard work....
									 */
									/*
									 * Get the certificate
									 */
									Certificate eCertInRO = Certificate
											.getInstance(((ASN1TaggedObject) replyObjects
													.getObjectAt(0))
													.getObject());
									System.out.println("cert:\t\t\t"
											+ eCertInRO.getSubject());
									/*
									 * Get the statusCode
									 */
									ASN1Enumerated statusCode = ASN1Enumerated
											.getInstance(replyObjects
													.getObjectAt(1));
									System.out.println("replyStatus:\t\t"
											+ statusCode.getValue().toString());
									/*
									 * Get the time of validation
									 */
									ASN1GeneralizedTime replyValTime = ASN1GeneralizedTime
											.getInstance(replyObjects
													.getObjectAt(2));
									System.out.println("replyValTime:\t\t"
											+ replyValTime.getTimeString());
									/*
									 * Get the reply checks
									 */
									ASN1Sequence replyChecks = ASN1Sequence
											.getInstance(replyObjects
													.getObjectAt(3));
									@SuppressWarnings("unchecked")
									Enumeration<ASN1Sequence> rcEn = replyChecks
											.getObjects();
									int rcNum = 0;
									while (rcEn.hasMoreElements()) {
										ASN1Sequence replyCheck = rcEn
												.nextElement();
										ASN1ObjectIdentifier check = (ASN1ObjectIdentifier) replyCheck
												.getObjectAt(0);
										System.out.println("replyCheck("
												+ rcNum + "):check:\t"
												+ check.getId());
										ASN1Integer status = (ASN1Integer) replyCheck
												.getObjectAt(1);
										System.out.println("replyCheck("
												+ rcNum + "):status:\t"
												+ status.toString());
										rcNum++;
									}
									/*
									 * Get the reply wantBacks (although we
									 * asked for none)
									 */
									ASN1Sequence replyWantBacks = ASN1Sequence
											.getInstance(replyObjects
													.getObjectAt(4));
									@SuppressWarnings("unchecked")
									Enumeration<ASN1Sequence> rcWB = replyWantBacks
											.getObjects();
									int wbNum = 0;
									while (rcWB.hasMoreElements()) {
										ASN1Sequence replyWantBack = rcWB
												.nextElement();
										ASN1ObjectIdentifier wb = (ASN1ObjectIdentifier) replyWantBack
												.getObjectAt(0);
										System.out.println("replyWantBack("
												+ wbNum + "):wb:\t"
												+ wb.getId());
										ASN1Integer check = (ASN1Integer) replyWantBack
												.getObjectAt(1);
										System.out.println("replyWantBack("
												+ wbNum + "):value:\t"
												+ check.toString());
										wbNum++;
									}
									Object rcObj = replyObjects.getObjectAt(5);
									System.out.println(rcObj);
								} else {
									throw new SCVPException(
											"No ReplyObjects in CVResponse");
								}
							} else {
								throw new SCVPException(
										"Invalid SCVP Signature: Signature Validation Failed");
							}
						} else {
							throw new SCVPException(
									"The SignerIdentifier and Signing Certificate do not match");
						}
					} else {
						throw new SCVPException(
								"Response from the server is not a CMS message");
					}
				} else {
					throw new SCVPException(
							"Response from the server is not a CMS SignedData message");
				}
			} else {
				throw new SCVPException(
						"Response from the server is not a CMS SignedData message");
			}
		} else {
			throw new SCVPException(
					"Response from the server is not a CMS SignedData message");
		}
		// if (sdParser != null) {
		// System.out.println("SD Parser not null.");
		// ASN1Integer sdv = sdParser.getVersion();
		// System.out.println("SignedData Version:\t" + sdv.toString());
		// ASN1SetParser sdda = sdParser.getDigestAlgorithms();
		// ASN1SequenceParser sddas = (ASN1SequenceParser)sdda.readObject();
		// ASN1ObjectIdentifier digestAlg =
		// (ASN1ObjectIdentifier)sddas.readObject();
		// System.out.println("Digest Algorithm:\t" + digestAlg.toString());
		// ASN1SetParser sdc = sdParser.getCertificates();
		// ASN1SequenceParser sdcs = (ASN1SequenceParser)sdc.readObject();
		// sdParser.getCrls();
		// ContentInfoParser sdeci = sdParser.getEncapContentInfo();
		//
		// //System.out.println(contentInfoParser.getContentType().getId());
		// //CVResponseParser cvResParse =
		// CVResponseParser.getInstance(contentInfoParser.getContent(2));
		// }
		/*
		 * Somewhat psudocode, but not. TODO: make it happen.
		 * 
		 * Let's say this is the cart before the horse...
		 * 
		 * To validate the response, we need the SCVP signer cert and the
		 * request.
		 * 
		 * I.e., CVResponseVerifier
		 * 
		 * The response objects and artifacts will be populated by BC's notion
		 * of "Parsers"
		 * 
		 * I.e., CVResponseParser, ReplyStatusParser, CertReplyParser, etc...
		 * 
		 * Scratch that. We have one big builder, we will have one big parser.
		 */
		// CVResponse cvResponse = cvResponse.getEncoded();
		// if (cvResponse != null) {
		// /*
		// * verify that the response can be trusted
		// */
		// CVResponseVerifier verifier = new CVResponseVerifier(cvRequest,
		// cvResponse);
		// verifier.verify(signerCert);
		//
		// switch (cvResponse.getReplyStatus()) {
		// case ReplyStatus.success: {
		// /*
		// * Bottom line, if the replyStatus is anything other
		// * than ReplyStatus.success, then it is invalid...
		// */
		// valid = true;
		// System.out.println("success");
		// break;
		// }
		// case ReplyStatus.malformedPKC: {
		// System.out.println("malformedPKC");
		// break;
		// }
		// case ReplyStatus.malformedAC: {
		// System.out.println("malformedAC");
		// break;
		// }
		// case ReplyStatus.unavailableValidationTime: {
		// System.out.println("unavailableValidationTime");
		// break;
		// }
		// case ReplyStatus.referenceCertHashFail: {
		// System.out.println("referenceCertHashFail");
		// break;
		// }
		// case ReplyStatus.certPathConstructFail: {
		// System.out.println("certPathConstructFail");
		// break;
		// }
		// case ReplyStatus.certPathNotValid: {
		// System.out.println("certPathNotValid");
		// break;
		// }
		// case ReplyStatus.certPathNotValidNow: {
		// System.out.println("certPathNotValidNow");
		// break;
		// }
		// case ReplyStatus.wantBackUnsatisfied: {
		// System.out.println("wantBackUnsatisfied");
		// break;
		// }
		// default: {
		// System.out.println("Unknown");
		// break;
		// }
		// }
		// /*
		// * sample of data's extraction from the CvResponse
		// */
		// for (CertReply certReply : cvResponse.getReplyObjects()) {
		// /*
		// * If validation error, print
		// */
		// List<String> errors = certReply.getValidationErrors();
		// if (errors != null && !errors.isEmpty()) {
		// System.out.print("ValidationErrors: ");
		// for (String errOid : errors) {
		// if (errOid.equalsIgnoreCase("1.3.6.1.5.5.7.19.3.1")) {
		// System.out
		// .print("1.3.6.1.5.5.7.19.3.1 (id-bvae-expired) ");
		// } else if (errOid
		// .equalsIgnoreCase("1.3.6.1.5.5.7.19.3.2")) {
		// System.out
		// .print("1.3.6.1.5.5.7.19.3.2 (id-bvae-notYetValid) ");
		// } else if (errOid
		// .equalsIgnoreCase("1.3.6.1.5.5.7.19.3.3")) {
		// System.out
		// .print("1.3.6.1.5.5.7.19.3.3 (id-bvae-wrongTrustAnchor) ");
		// } else if (errOid
		// .equalsIgnoreCase("1.3.6.1.5.5.7.19.3.4")) {
		// System.out
		// .print("1.3.6.1.5.5.7.19.3.4 (id-bvae-noValidCertPath) ");
		// } else if (errOid
		// .equalsIgnoreCase("1.3.6.1.5.5.7.19.3.5")) {
		// System.out
		// .print("1.3.6.1.5.5.7.19.3.5 (id-bvae-revoked) ");
		// } else if (errOid
		// .equalsIgnoreCase("1.3.6.1.5.5.7.19.3.6")) {
		// System.out
		// .print("1.3.6.1.5.5.7.19.3.6 (id-bvae-6) ");
		// } else if (errOid
		// .equalsIgnoreCase("1.3.6.1.5.5.7.19.3.7")) {
		// System.out
		// .print("1.3.6.1.5.5.7.19.3.7 (id-bvae-7) ");
		// } else if (errOid
		// .equalsIgnoreCase("1.3.6.1.5.5.7.19.3.8")) {
		// System.out
		// .print("1.3.6.1.5.5.7.19.3.8 (id-bvae-8) ");
		// } else if (errOid
		// .equalsIgnoreCase("1.3.6.1.5.5.7.19.3.9")) {
		// System.out
		// .print("1.3.6.1.5.5.7.19.3.9 (id-bvae-invalidKeyPurpose) ");
		// } else if (errOid
		// .equalsIgnoreCase("1.3.6.1.5.5.7.19.3.10")) {
		// System.out
		// .print("1.3.6.1.5.5.7.19.3.10 (id-bvae-invalidKeyUsage) ");
		// } else if (errOid
		// .equalsIgnoreCase("1.3.6.1.5.5.7.19.3.11")) {
		// System.out
		// .print("1.3.6.1.5.5.7.19.3.11 (id-bvae-invalidCertPolicy) ");
		// } else {
		// System.out.print(errOid + " (unknown) ");
		// }
		// }
		// System.out.println();
		// }
		// }
		// } else {
		// //cvResponse was null!
		// }
		System.out.println("Finished in "
				+ (System.currentTimeMillis() - start) + " milliseconds.");
	}

	/*
	 * This is not my preferable path... TODO: Replace transport with Apache
	 * HTTP client
	 */
	public static byte[] sendSCVPRequestPOST(String postURL, byte[] req)
			throws SCVPException {
		byte[] resp = null;
		try {
			URL url = new URL(postURL);
			URLConnection con = url.openConnection();
			con.setReadTimeout(10000);
			con.setConnectTimeout(10000);
			con.setAllowUserInteraction(false);
			con.setUseCaches(false);
			con.setDoOutput(true);
			con.setDoInput(true);
			con.setRequestProperty("Content-Type",
					"application/scvp-cv-request");
			OutputStream os = con.getOutputStream();
			os.write(req);
			os.close();
			/*
			 * Lets make sure we are receiving an SCVP response...
			 */
			if (con.getContentType().equalsIgnoreCase(
					"application/scvp-cv-response")) {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				byte[] chunk = new byte[4096];
				int bytesRead;
				InputStream stream = con.getInputStream();
				while ((bytesRead = stream.read(chunk)) > 0) {
					baos.write(chunk, 0, bytesRead);
				}
				resp = baos.toByteArray();
			} else {
				throw new SCVPException(
						"Response from the server is not a CMS message");
			}
		} catch (IOException e) {
			throw new SCVPException("Problem communicating with SCVP server", e);
		}
		return resp;
	}

}
