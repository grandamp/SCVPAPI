package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/*
 *       CertReply ::= SEQUENCE {
        cert                       CertReference,
        replyStatus                ReplyStatus DEFAULT success,
        replyValTime               GeneralizedTime,
        replyChecks                ReplyChecks,
        replyWantBacks             ReplyWantBacks,
        validationErrors       [0] SEQUENCE SIZE (1..MAX) OF
                                     OBJECT IDENTIFIER OPTIONAL,
        nextUpdate             [1] GeneralizedTime OPTIONAL,
        certReplyExtensions    [2] Extensions OPTIONAL }

 */
public class CertReply extends ASN1Object {

	public CertReply() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		// TODO Auto-generated method stub
		return null;
	}

}
