package org.keysupport.bc.scvp.asn1;

import java.util.Vector;

import org.bouncycastle.asn1.ASN1Object;

public class RevocationInfos extends SeqOfASN1Object {

	public RevocationInfos(Vector<ASN1Object> objs) {
		super(objs);
	}

}
