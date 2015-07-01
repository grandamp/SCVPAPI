package org.keysupport.bc.scvp.asn1;

import java.util.Vector;

import org.bouncycastle.asn1.ASN1Object;

public class UserPolicySet extends SeqOfASN1Object {

	public UserPolicySet(Vector<ASN1Object> oids) {
		super(oids);
	}

	public UserPolicySet() {
	}

}
