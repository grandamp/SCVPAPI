package org.keysupport.bc.scvp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
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
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

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
import org.bouncycastle.asn1.util.ASN1Dump;
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

	private static final Logger log = Logger.getLogger(ExampleSCVPClient.class.getPackage().getName());
	private Provider jceProvider = null;
	private byte[] fullRequest = null;
	private byte[] fullResponse = null;

	public ExampleSCVPClient(Provider jceProvider) {
		this.jceProvider = jceProvider;
	}

	public static void usage() {
		System.out.println("usage:  java -jar SCVPAPI.jar <scvp_url> <certificate_filename> <polOID> <polOID> <polOID> <polOID> ...");
	}

	public static void main(String args[]) {

		/*
		 * We are going to override the platform logger for
		 * this example and throw all messages to the console.
		 */
		log.setUseParentHandlers(false);
		ConsoleHandler handler = new ConsoleHandler();
		log.setLevel(Level.ALL);
		handler.setLevel(Level.ALL);
		log.addHandler(handler);
		
		/*
		 * The intent is to change the provider for the cryptographic
		 * operations. I.e., a FIPS provider if needed. For now, we will use the
		 * BouncyCastle API since that is what we use for the ASN.1
		 */
		if (args.length <= 2) {
			usage();
			return;
		}
		Provider jceProvider = new BouncyCastleProvider();
		Security.addProvider(jceProvider);
		ExampleSCVPClient client = new ExampleSCVPClient(jceProvider);
		String scvpUrl = args[0];
		String certFile = args[1];
		int i=2;
		List<String> policyOids = new ArrayList<String>();
		while (i != args.length) {
			/*
			 * Syntax check for the OIDS
			 */
			try {
				ASN1ObjectIdentifier id = new ASN1ObjectIdentifier(args[i]);
				log.log(Level.INFO, "Including Policy: " + id.getId());
				policyOids.add(id.toString());
			} catch(IllegalArgumentException e) {
				log.log(Level.SEVERE, "Invalid Policy OID:" + args[i] + ":" + e.getLocalizedMessage());
			}
			i++;
		}
		X509Certificate endEntityCert;
		try {

			CertificateFactory cf;
				cf = CertificateFactory.getInstance("X.509", jceProvider.getName());
			endEntityCert = (X509Certificate) cf
					.generateCertificate(new FileInputStream(certFile));

			if (client.validate(scvpUrl, endEntityCert, policyOids)) {
				log.log(Level.INFO, "Certificate validated successfully.");
			} else {
				log.log(Level.INFO, "Certificate not valid.");
			}
		} catch (SCVPException e) {
			log.log(Level.SEVERE, "There was a problem: " + e.getMessage());
		} catch (NoSuchProviderException e) {
			log.log(Level.SEVERE, "There was a problem with the JCE provider: " + e.getMessage());
		} catch (CertificateException e) {
			log.log(Level.SEVERE, "There was a problem with the certificate: " + e.getMessage());
		} catch (FileNotFoundException e) {
			log.log(Level.SEVERE, "No such file: " + certFile);
		}
	}

	public boolean validate(String scvpServer, X509Certificate endEntityCert, List<String> policyOids) throws SCVPException {
		boolean certificateValid = false;
		long start = System.currentTimeMillis();
		ByteArrayInputStream bais;
		Certificate eCert;
		try {
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
		log.log(Level.INFO, "Client Cert Subject:\t"
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
		//TODO:  Add code to add Trust Anchor
		// builder.addTrustAnchors(trustAnchor);
		
		//TODO:  Add input for validation policy identifier
		builder.setValidationPolRef(new ASN1ObjectIdentifier(
				"1.3.6.1.5.5.7.19.1"), null);

		for (String s: policyOids) {
			builder.addUserPolicy(new ASN1ObjectIdentifier(s));
		}
		/*
		 * These are the additional RFC-5280 inputs:
		 * 
		 * We do not allow wild-card policy assertions (InhibitAnyPolicy). We
		 * require the policy oids to be present in all certs within the path
		 * (RequireExplicitPolicy). We allow mapped policies in place of the
		 * explicitly defined inital policy set.
		 */
		//TODO:  Add code to set the following inputs
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
		//TODO:  Add Classes based off of the client profile document
		builder.setRequestorName("URN:ValidationService:TEST:SCVPExample");
		builder.setRequestorText("LOG;HI;MAJ;OTH;APP,https://github.com/grandamp/SCVPAPI/,-");
		/*
		 * Adding a 16 byte nonce
		 */
		//TODO:  Create an input for the nonce
		builder.generateNonce(16);
		/*
		 * Final assembly of the request.
		 */
		SCVPRequest req = builder.buildRequest();
		log.log(Level.FINE, "SCVPRequest:\n" + ASN1Dump.dumpAsString(req, true));
		byte[] rawReq;
		try {
			rawReq = req.toASN1Primitive().getEncoded();
		} catch (IOException e) {
			throw new SCVPException("Problem with SCVP Request", e);
		}
		this.fullRequest = rawReq;
		/*
		 * Send the request to the SCVP service...
		 */
		byte[] resp = sendSCVPRequestPOST(scvpServer, rawReq);
		this.fullResponse = resp;
		
		certificateValid = validateSCVPResponse(resp);

		log.log(Level.INFO, "Finished in " + (System.currentTimeMillis() - start) + " milliseconds.");
		return certificateValid;
	}

	public boolean validateSCVPResponse(byte[] resp) throws SCVPException {
		boolean certificateValid = false;

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

						/*
						 * The following is for logging, but we may switch to
						 * decoding the response directly using a primitive, vs
						 * trying to use the decoders.  Not certain if there is
						 * a bug, but the decoders interpret some of the data
						 * as BER and not DER :/
						 */
						ASN1Sequence ppResp = null;
						try {
							ppResp = (ASN1Sequence) ASN1Sequence.fromByteArray(resp);
						} catch (IOException e) {
							throw new SCVPException(
									"Problem parsing response from server", e);
						}
						log.log(Level.FINE, ASN1Dump.dumpAsString(ppResp, true));
						/*
						 * 
						 */

						// version CMSVersion
						ASN1Integer sdv;
						try {
							sdv = (ASN1Integer) cmsSdPar.readObject();
						} catch (IOException e) {
							throw new SCVPException(
									"Problem parsing CMS Version", e);
						}
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
						ASN1SequenceParser eCInfoPar;
						ASN1ObjectIdentifier eContentType;
						ASN1TaggedObjectParser eContent;
						ASN1OctetString cVResponse;
						try {
							eCInfoPar = (ASN1SequenceParser) cmsSdPar
									.readObject();
							eContentType = (ASN1ObjectIdentifier) eCInfoPar
									.readObject();
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
							AlgorithmIdentifier sIAlgId = sInfo
									.getDigestAlgorithm();
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
								Calendar minBefore = new GregorianCalendar();
								Calendar minAfter = new GregorianCalendar();
								minBefore.add(Calendar.MINUTE, -1);
								minAfter.add(Calendar.MINUTE, 1);
								if (!(currentTime.before(minBefore) || currentTime
										.after(minAfter))) {
								} else {
									throw new SCVPException(
											"Unacceptable Signing Time: "
													+ claimSignTime
															.getAdjustedTime());
								}
								ASN1OctetString claimDigestOS = (ASN1OctetString) siMessageDigest
										.getAttrValues().getObjectAt(0);
								byte[] claimDigest = claimDigestOS.getOctets();
								if (Arrays.areEqual(digest, claimDigest)) {
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
							CertificateFactory cf;
							X509Certificate cvSignerCert;
							try {
								cf = CertificateFactory.getInstance("X.509",
										jceProvider.getName());
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
							} catch (NoSuchProviderException e) {
								throw new SCVPException(
										"Problem with JCE Provider", e);
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
								/*
								 * TODO: Validate that we trust the SCVP Signer
								 * certificate:
								 * 
								 * To elaborate, while this code does validate the signature 
								 * of the SCVP response, it does not verify the signer 
								 * certificate is one that we "trust".  Further, a large
								 * fault-tolerant SCVP service MAY have multiple SCVP signers.
								 * To specify explicit trust in those signers as a command
								 * line option, or as inputs to this code is counter-intuitive,
								 * as SCVP is intended to ease the burden of managing trust lists.
								 * 
								 * So for this implementation, the SCVP signing certificate MUST chain
								 * to one specific trust anchor.  There MUST be a policy on the SCVP
								 * service that supports validation of all SCVP signers encountered
								 * to that trust anchor.  It is up to the implementor how often
								 * the SCVP signer is validated, vs. reliance on a cached CVResponse
								 * of the prior validation.
								 * 
								 */ 
								 /* 
								 * Now we will process the CVResponse, verify
								 * the response from the request artifacts, and
								 * then return a result for human (or other IT
								 * Logic) consumption. We will render the
								 * CVResponse from the response bytes we
								 * digested (used for signature validation).
								 */
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
									serverConfigurationID = ASN1Integer
											.getInstance(cvResp.readObject());
									producedAt = ASN1GeneralizedTime
											.getInstance(cvResp.readObject());
									responseStatus = ASN1Sequence
											.getInstance(cvResp.readObject());
									ASN1Enumerated statusCode = ASN1Enumerated
											.getInstance(responseStatus
													.getObjectAt(0));
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
											break;
										}
										case 1: {
											requestRef = (ASN1TaggedObject) atObjFp
													.getObject();
											break;
										}
										case 2: {
											requestorRef = (ASN1Sequence) atObjFp
													.getObject();
											break;
										}
										case 3: {
											requestorName = (ASN1Sequence) atObjFp
													.getObject();
											break;
										}
										case 4: {
											replyObjects = (ASN1Sequence) atObjFp
													.getObject();
											break;
										}
										case 5: {
											respNonce = (ASN1OctetString) atObjFp
													.getObject();
											break;
										}
										case 6: {
											serverContextInfo = (ASN1OctetString) atObjFp
													.getObject();
											break;
										}
										case 7: {
											cvResponseExtensions = (ASN1Sequence) atObjFp
													.getObject();
											break;
										}
										case 8: {
											requestorText = (ASN1OctetString) atObjFp
													.getObject();
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
									/*
									 * Get the statusCode
									 */
									ASN1Enumerated statusCode = ASN1Enumerated
											.getInstance(replyObjects
													.getObjectAt(1));
									/*
									 * Get the time of validation
									 */
									ASN1GeneralizedTime replyValTime = ASN1GeneralizedTime
											.getInstance(replyObjects
													.getObjectAt(2));
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
										ASN1Integer status = (ASN1Integer) replyCheck
												.getObjectAt(1);
										if (status.getValue().equals(BigInteger.ZERO)) {
											certificateValid = true; 
										}
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
										ASN1Integer check = (ASN1Integer) replyWantBack
												.getObjectAt(1);
										wbNum++;
									}
									Object rcObj = replyObjects.getObjectAt(5);
									/*
									 * Return our validation boolean
									 */
									
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
		return certificateValid;
	}

	/*
	 * This is not my preferable path... TODO: Replace transport with Apache
	 * HTTP client.
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

	/**
	 * @return the fullRequest
	 */
	public byte[] getFullRequest() {
		return fullRequest;
	}

	/**
	 * @return the fullResponse
	 */
	public byte[] getFullResponse() {
		return fullResponse;
	}

}
