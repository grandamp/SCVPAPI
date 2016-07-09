package org.keysupport.bc.scvp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;
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
import org.keysupport.bc.scvp.asn1.ResponseTypes;
import org.keysupport.bc.scvp.asn1.RevocationInfoTypes;
import org.keysupport.bc.scvp.asn1.ServerPolicyRequest;
import org.keysupport.bc.scvp.asn1.ValPolRequest;
import org.keysupport.crypto.CipherEngine;
import org.keysupport.crypto.DigestEngine;
import org.keysupport.util.DataUtil;

public class ServerPolicyClient {

	private static final Logger log = Logger.getLogger(ServerPolicyClient.class.getPackage().getName());
	private Provider jceProvider = null;
	private byte[] fullRequest = null;
	private byte[] fullResponse = null;

	public ServerPolicyClient(Provider jceProvider) {
		this.jceProvider = jceProvider;
	}

	public static void usage() {
		System.out.println("usage:  java -jar SCVPAPI.jar <scvp_url>");
	}

	public static void main(String args[]) throws SCVPException {

		/*
		 * We are going to override the platform logger for
		 * this example and throw all messages to the console.
		 */
		log.setUseParentHandlers(false);
		ConsoleHandler handler = new ConsoleHandler();
		log.setLevel(Level.ALL);
		handler.setLevel(Level.ALL);
		log.addHandler(handler);
		String scvpUrl = null;
		if (args.length <= 0) {
			//usage();
			//return;
			scvpUrl = "http://vs.treas.gov";
		} else {
			scvpUrl = args[0];
		}
		Provider jceProvider = new BouncyCastleProvider();
		Security.addProvider(jceProvider);
		ServerPolicyClient client = new ServerPolicyClient(jceProvider);
		client.serverPolicyQuery(scvpUrl);
	}

	public ASN1OctetString generateNonce(int nonceSize) {
		SecureRandom random = null;
		byte[] nonce = null;
		nonce = new byte[nonceSize];
		random = new SecureRandom();
		random.nextBytes(nonce);
		return new DEROctetString(nonce);
	}

	public void serverPolicyQuery(String scvpServer) throws SCVPException {
		ValPolRequest policyRequest = new ValPolRequest(generateNonce(16));
		ServerPolicyRequest encapReq = new ServerPolicyRequest(policyRequest);
		log.log(Level.FINE, "ValPolRequest:\n" + ASN1Dump.dumpAsString(encapReq, true));
		byte[] rawReq;
		try {
			rawReq = encapReq.toASN1Primitive().getEncoded();
		} catch (IOException e) {
			throw new SCVPException("Problem with SCVP Policy Request", e);
		}
		this.fullRequest = rawReq;
		/*
		 * Send the request to the SCVP service...
		 */
		byte[] resp = sendSCVPRequestPOST(scvpServer, rawReq);
		this.fullResponse = resp;
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
						ASN1OctetString valPolResponse;
						try {
							eCInfoPar = (ASN1SequenceParser) cmsSdPar
									.readObject();
							eContentType = (ASN1ObjectIdentifier) eCInfoPar
									.readObject();
							eContent = (ASN1TaggedObjectParser) eCInfoPar
									.readObject();
							valPolResponse = (ASN1OctetString) eContent
									.getObjectParser(0, true).toASN1Primitive();
						} catch (IOException e) {
							throw new SCVPException(
									"Problem parsing EncapsulatedContentInfo",
									e);
						}
						/*
						 * Digest the object bytes for signature validation
						 */
						byte[] vPRespBytes = valPolResponse.getOctets();
						byte[] digest = null;
						/*
						 * Only support SHA-1/SHA-256/SHA-384. Die on validation
						 * otherwise.
						 */
						if (algId.getAlgorithm().equals(CipherEngine.SHA384)) {
							/*
							 * SHA-384
							 */
							digest = DigestEngine.sHA384Sum(vPRespBytes,
									jceProvider.getName());
						} else if (algId.getAlgorithm().equals(
								CipherEngine.SHA256)) {
							/*
							 * SHA-256
							 */
							digest = DigestEngine.sHA256Sum(vPRespBytes,
									jceProvider.getName());
						} else if (algId.getAlgorithm().equals(
								CipherEngine.SHA1)) {
							/*
							 * SHA-1
							 */
							digest = DigestEngine.sHA1Sum(vPRespBytes,
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
										"1.2.840.113549.1.9.16.1.13"))) {
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
								 * Begin parsing ValPolResponse
								 */
								ASN1StreamParser vpRespOs = new ASN1StreamParser(
										vPRespBytes);
								ASN1SequenceParser vpResp;
								ASN1Integer vpResponseVersion = null;
								ASN1Integer maxCVRequestVersion = null;
								ASN1Integer maxVPRequestVersion = null;
								ASN1Integer serverConfigurationID = null;
								ASN1GeneralizedTime thisUpdate = null;
								ASN1GeneralizedTime nextUpdate = null;
								ASN1Sequence supportedChecks = null;
								ASN1Sequence supportedWantBacks = null;
								ASN1Sequence validationPolicies = null;
								ASN1Sequence validationAlgs = null;
								ASN1Sequence authPolicies = null;
								ResponseTypes responseTypes = null;
								ASN1Sequence defaultPolicyValues = null;
								RevocationInfoTypes revocationInfoTypes = null;
								ASN1Sequence signatureGeneration = null;
								ASN1Sequence signatureVerification = null;
								ASN1Sequence hashAlgorithms = null;
								ASN1Sequence serverPublicKeys = null;
								ASN1Integer clockSkew = null;
								ASN1OctetString requestNonce = null;
								try {
									vpResp = (ASN1SequenceParser) vpRespOs
											.readObject();
									vpResponseVersion = ASN1Integer
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "vpResponseVersion:\n" + ASN1Dump.dumpAsString(vpResponseVersion, true));
									maxCVRequestVersion = ASN1Integer
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "maxCVRequestVersion:\n" + ASN1Dump.dumpAsString(maxCVRequestVersion, true));
									maxVPRequestVersion = ASN1Integer
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "maxVPRequestVersion:\n" + ASN1Dump.dumpAsString(maxVPRequestVersion, true));
									serverConfigurationID = ASN1Integer
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "serverConfigurationID:\n" + ASN1Dump.dumpAsString(serverConfigurationID, true));
									thisUpdate = ASN1GeneralizedTime
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "thisUpdate:\n" + ASN1Dump.dumpAsString(thisUpdate, true));
									nextUpdate = ASN1GeneralizedTime
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "nextUpdate:\n" + ASN1Dump.dumpAsString(nextUpdate, true));
									supportedChecks = ASN1Sequence
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "supportedChecks:\n" + ASN1Dump.dumpAsString(supportedChecks, true));
									supportedWantBacks = ASN1Sequence
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "supportedWantBacks:\n" + ASN1Dump.dumpAsString(supportedWantBacks, true));
									validationPolicies = ASN1Sequence
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "validationPolicies:\n" + ASN1Dump.dumpAsString(validationPolicies, true));
									validationAlgs = ASN1Sequence
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "validationAlgs:\n" + ASN1Dump.dumpAsString(validationAlgs, true));
									authPolicies = ASN1Sequence
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "authPolicies:\n" + ASN1Dump.dumpAsString(authPolicies, true));
									responseTypes = ResponseTypes
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "responseTypes:\n" + ASN1Dump.dumpAsString(responseTypes, true));
									defaultPolicyValues = ASN1Sequence
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "defaultPolicyValues:\n" + ASN1Dump.dumpAsString(defaultPolicyValues, true));
									revocationInfoTypes = RevocationInfoTypes
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "revocationInfoTypes:\n" + ASN1Dump.dumpAsString(revocationInfoTypes, true));
									signatureGeneration = ASN1Sequence
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "signatureGeneration:\n" + ASN1Dump.dumpAsString(signatureGeneration, true));
									signatureVerification = ASN1Sequence
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "signatureVerification:\n" + ASN1Dump.dumpAsString(signatureVerification, true));
									hashAlgorithms = ASN1Sequence
											.getInstance(vpResp.readObject());
									log.log(Level.FINE, "hashAlgorithms:\n" + ASN1Dump.dumpAsString(hashAlgorithms, true));
									/*
									 * The next defined object is optional, and not
									 * explicitly tagged.  Luckily, it is either a
									 * SEQUENCE (optional object) or an INTEGER 
									 * (the following mandatory object).
									 */
									Object nextObj = vpResp.readObject();
									if (nextObj instanceof ASN1Sequence) {
										/*
										 * Process
										 */
										serverPublicKeys = ASN1Sequence
												.getInstance(vpResp.readObject());
										log.log(Level.FINE, "serverPublicKeys:\n" + ASN1Dump.dumpAsString(serverPublicKeys, true));
										/*
										 * Pull the next object,
										 * which is mandatory.
										 */
										nextObj = vpResp.readObject();
									}
									clockSkew = ASN1Integer
											.getInstance(nextObj);
									log.log(Level.FINE, "clockSkew:\n" + ASN1Dump.dumpAsString(clockSkew, true));
									/*
									 * The following (and final) 
									 * object is also optional
									 */
									nextObj = vpResp.readObject();
									if (null != nextObj) {
										requestNonce = ASN1OctetString
												.getInstance(nextObj);
										log.log(Level.FINE, "requestNonce:\n" + ASN1Dump.dumpAsString(requestNonce, true));
									}
									/*
									 * Finished parsing ValPolResponse
									 */
								} catch (IOException e) {
									throw new SCVPException(
											"Error parsing CVResponse", e);
								}

							}
						}
					}
				}
			}
		}

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
					"application/scvp-vp-request");
			con.setRequestProperty("Accept",
					"application/scvp-vp-response");
			OutputStream os = con.getOutputStream();
			os.write(req);
			os.close();
			/*
			 * Lets make sure we are receiving an SCVP response...
			 */
			if (con.getContentType().equalsIgnoreCase(
					"application/scvp-vp-response")) {
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
