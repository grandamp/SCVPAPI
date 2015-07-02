package org.keysupport.bc.scvp.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/*
 *       ResponseStatus ::= SEQUENCE {
        statusCode            CVStatusCode DEFAULT  okay,
        errorMessage          UTF8String OPTIONAL }
 */
public class ResponseStatus extends ASN1Object {

	private ASN1Sequence value = null;
	private CVStatusCode statusCode = null;
	private DERUTF8String errorMessage = null;

	private ResponseStatus(ASN1Sequence value) {
		this.value = value;
	}

	public ResponseStatus(CVStatusCode statusCode, DERUTF8String errorMessage) {
		this.statusCode = statusCode;
		this.errorMessage = errorMessage;
	}

	public static ResponseStatus getInstance(Object obj) {
		if (obj instanceof ResponseStatus) {
			return (ResponseStatus) obj;
		} else if (obj != null) {
			return new ResponseStatus(ASN1Sequence.getInstance(obj));
		}
		return null;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(statusCode);
		if (errorMessage!= null) {
			v.add(errorMessage);
		}
		return new DERSequence(v);
	}

}
