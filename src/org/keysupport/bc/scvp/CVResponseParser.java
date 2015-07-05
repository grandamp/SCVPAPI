package org.keysupport.bc.scvp;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.keysupport.bc.scvp.asn1.ReplyObjects;
import org.keysupport.bc.scvp.asn1.RequestReference;
import org.keysupport.bc.scvp.asn1.ResponseStatus;
import org.keysupport.bc.scvp.asn1.ValidationPolicy;

/**
 * Parser for SCVPResponse
 * <p>
 * 
 * This parser is intended to parse a typical signed SCVP response,
 * where the request was an unsigned DPV request with minimal contents.
 * <pre>
 *       ContentInfo ::= SEQUENCE {
 *        contentType ContentType,
 *        content [0] EXPLICIT ANY DEFINED BY contentType }
 *
 *       ContentType ::= OBJECT IDENTIFIER
 *
 *       SignedData ::= SEQUENCE {
 *        version CMSVersion,
 *        digestAlgorithms DigestAlgorithmIdentifiers,
 *        encapContentInfo EncapsulatedContentInfo,
 *        certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *        signerInfos SignerInfos }
 *
 *      EncapsulatedContentInfo ::= SEQUENCE {
 *        eContentType ContentType,
 *        eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 *
 *      ContentType ::= OBJECT IDENTIFIER
 *
 *       CVResponse ::= SEQUENCE {
 *        cvResponseVersion         INTEGER,
 *        serverConfigurationID     INTEGER,
 *        producedAt                GeneralizedTime,
 *        responseStatus            ResponseStatus,
 *        respValidationPolicy  [0] RespValidationPolicy OPTIONAL,
 *        requestRef            [1] RequestReference OPTIONAL,
 *        requestorRef          [2] GeneralNames OPTIONAL,
 *        requestorName         [3] GeneralNames OPTIONAL,
 *        replyObjects          [4] ReplyObjects OPTIONAL,
 *        respNonce             [5] OCTET STRING OPTIONAL,
 *        serverContextInfo     [6] OCTET STRING OPTIONAL,
 *        cvResponseExtensions  [7] Extensions OPTIONAL,
 *        requestorText         [8] UTF8String (SIZE (1..256)) OPTIONAL }
 *
 *       RespValidationPolicy ::= ValidationPolicy
 *
 *       ValidationPolicy ::= SEQUENCE {
 *        validationPolRef          ValidationPolRef,
 *        validationAlg         [0] ValidationAlg OPTIONAL,
 *        userPolicySet         [1] SEQUENCE SIZE (1..MAX) OF OBJECT
 *                                    IDENTIFIER OPTIONAL,
 *        inhibitPolicyMapping  [2] BOOLEAN OPTIONAL,
 *        requireExplicitPolicy [3] BOOLEAN OPTIONAL,
 *        inhibitAnyPolicy      [4] BOOLEAN OPTIONAL,
 *        trustAnchors          [5] TrustAnchors OPTIONAL,
 *        keyUsages             [6] SEQUENCE OF KeyUsage OPTIONAL,
 *        extendedKeyUsages     [7] SEQUENCE OF KeyPurposeId OPTIONAL,
 *        specifiedKeyUsages    [8] SEQUENCE OF KeyPurposeId OPTIONAL }
 *
 * </pre>
 */
public class CVResponseParser {
	
//	private ASN1Integer cvResponseVersion = null;
//	private ASN1Integer serverConfigurationID = null;
//	private ASN1GeneralizedTime producedAt = null;
//	private ResponseStatus responseStatus = null;
//	private ValidationPolicy respValidationPolicy = null;
//	private RequestReference requestRef = null;
//	private GeneralNames requestorRef = null;
//	private GeneralNames requestorName = null;
//	private ReplyObjects replyObjects = null;
//	private ASN1OctetString respNonce = null;
//	private ASN1OctetString serverContextInfo = null;
//	private Extensions cvResponseExtensions = null;
	//private DERUTF8String requestorText = null;

	private ASN1SequenceParser _seq;
	private ASN1Integer _cvResponseVersion;
	private ASN1Integer _serverConfigurationID;
	private ASN1GeneralizedTime _producedAt;
	private ResponseStatus _responseStatus;
	private Object _nextObject;

	public static CVResponseParser getInstance(Object o) throws IOException {
		if (o instanceof ASN1Sequence) {
			return new CVResponseParser(((ASN1Sequence) o).parser());
		}
		if (o instanceof ASN1SequenceParser) {
			return new CVResponseParser((ASN1SequenceParser) o);
		}
		throw new IOException("unknown object encountered: "
				+ o.getClass().getName());
	}

	private CVResponseParser(ASN1SequenceParser seq) throws IOException {
		this._seq = seq;
		this._cvResponseVersion = (ASN1Integer) seq.readObject();
		this._serverConfigurationID = (ASN1Integer) seq.readObject();
		this._producedAt = (ASN1GeneralizedTime) seq.readObject();
		//this._responseStatus = (ResponseStatus) seq.readObject();
		_nextObject = _seq.readObject();
		if (_nextObject instanceof ASN1SequenceParser) {
			System.out.println("Sequence Parser!");
		} else {
			System.out.println(_nextObject.toString());
		}
	}

	public ASN1Integer getResponseVersion() {
		return _cvResponseVersion;
	}

	public ASN1Integer getServerConfigurationID() {
		return _serverConfigurationID;
	}
	
	public ASN1GeneralizedTime getProducedAt() {
		return _producedAt;
	}
	
	public ResponseStatus getResponseStatus() {
		return _responseStatus;
	}

}