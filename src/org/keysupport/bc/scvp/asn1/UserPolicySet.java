package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;

public class UserPolicySet extends SeqOfASN1Object {

	public UserPolicySet(ASN1EncodableVector oids) {
		super(oids);
	}

	public UserPolicySet() {
	}

}
