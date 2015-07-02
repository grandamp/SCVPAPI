package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;

/*
 *       CVResponse ::= SEQUENCE {
        cvResponseVersion         INTEGER,
        serverConfigurationID     INTEGER,
        producedAt                GeneralizedTime,
        responseStatus            ResponseStatus,
        respValidationPolicy  [0] RespValidationPolicy OPTIONAL,
        requestRef            [1] RequestReference OPTIONAL,
        requestorRef          [2] GeneralNames OPTIONAL,
        requestorName         [3] GeneralNames OPTIONAL,
        replyObjects          [4] ReplyObjects OPTIONAL,
        respNonce             [5] OCTET STRING OPTIONAL,
        serverContextInfo     [6] OCTET STRING OPTIONAL,
        cvResponseExtensions  [7] Extensions OPTIONAL,
        requestorText         [8] UTF8String (SIZE (1..256)) OPTIONAL }

 */
public class CVResponse extends ASN1Object {

	private ASN1Sequence seq = null;
	private ASN1Integer cvResponseVersion = null;
	private ASN1Integer serverConfigurationID = null;
	private ASN1GeneralizedTime producedAt = null;
	private ResponseStatus responseStatus = null;
	private ValidationPolicy respValidationPolicy = null;
	private RequestReference requestRef = null;
	private GeneralNames requestorRef = null;
	private GeneralNames requestorName = null;
	private ReplyObjects replyObjects = null;
	private ASN1OctetString respNonce = null;
	private ASN1OctetString serverContextInfo = null;
	private Extensions cvResponseExtensions = null;
	private DERUTF8String requestorText = null;
	
	private CVResponse(ASN1Sequence seq) {
		this.seq = seq;
	}

	

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		//v.add(...);
		return new DERSequence(v);
	}

}
