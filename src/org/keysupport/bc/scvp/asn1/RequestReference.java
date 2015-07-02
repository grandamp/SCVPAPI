package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/*
 *       RequestReference ::= CHOICE {
        requestHash       [0] HashValue, -- hash of CVRequest
        fullRequest       [1] CVRequest }

 */
public class RequestReference extends ASN1Object implements ASN1Choice {

	public RequestReference() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		// TODO Auto-generated method stub
		return null;
	}

}
