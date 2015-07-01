package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * @author tejohnson
 * 
 *         https://tools.ietf.org/html/rfc5055#section-3
 * 
 */

/*<pre>
 *      CVRequest ::= SEQUENCE {
        cvRequestVersion        INTEGER DEFAULT 1,
        query                   Query,
        requestorRef        [0] GeneralNames OPTIONAL,
        requestNonce        [1] OCTET STRING OPTIONAL,
        requestorName       [2] GeneralName OPTIONAL,
        responderName       [3] GeneralName OPTIONAL,
        requestExtensions   [4] Extensions OPTIONAL,
        signatureAlg        [5] AlgorithmIdentifier OPTIONAL,
        hashAlg             [6] OBJECT IDENTIFIER OPTIONAL,
        requestorText       [7] UTF8String (SIZE (1..256)) OPTIONAL }
 *</pre> 
 */

public class CVRequest extends ASN1Object {

	private final ASN1Integer cvRequestVersion = new ASN1Integer(1);
	private Query query = null;
	private GeneralNames requestorRef = null;
	private ASN1OctetString requestNonce = null;
	private GeneralName requestorName = null;
	private GeneralName responderName = null;
	private Extensions requestExtensions = null;
	private AlgorithmIdentifier signatureAlg = null;
	private ASN1ObjectIdentifier hashAlg = null;
	private DERUTF8String requestorText = null;

	public CVRequest(Query query, GeneralNames requestorRef,
			ASN1OctetString requestNonce, GeneralName requestorName,
			GeneralName responderName, Extensions requestExtensions,
			AlgorithmIdentifier signatureAlg, ASN1ObjectIdentifier hashAlg,
			DERUTF8String requestorText) {
		this.query = query;
		this.requestorRef = requestorRef;
		this.requestNonce = requestNonce;
		this.requestorName = requestorName;
		this.responderName = responderName;
		this.requestExtensions = requestExtensions;
		this.signatureAlg = signatureAlg;
		this.hashAlg = hashAlg;
		this.requestorText = requestorText;
	}

	private CVRequest(ASN1Sequence seq) {
	}

	public static CVRequest getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	public static CVRequest getInstance(Object obj) {
		if (obj instanceof CVRequest) {
			return (CVRequest) obj;
		} else if (obj != null) {
			return new CVRequest(ASN1Sequence.getInstance(obj));
		}
		return null;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(cvRequestVersion);
		v.add(query);
		if (requestorRef != null) {
			v.add(new DERTaggedObject(true, 0, requestorRef));
		}
		if (requestNonce != null) {
			v.add(new DERTaggedObject(true, 1, requestNonce));
		}
		if (requestorName != null) {
			v.add(new DERTaggedObject(true, 2, requestorName));
		}
		if (responderName != null) {
			v.add(new DERTaggedObject(true, 3, responderName));
		}
		if (requestExtensions != null) {
			v.add(new DERTaggedObject(true, 4, requestExtensions));
		}
		if (signatureAlg != null) {
			v.add(new DERTaggedObject(true, 5, signatureAlg));
		}
		if (hashAlg != null) {
			v.add(new DERTaggedObject(true, 6, hashAlg));
		}
		if (requestorText != null) {
			v.add(new DERTaggedObject(true, 7, requestorText));
		}
		return new DERSequence(v);
	}

}
