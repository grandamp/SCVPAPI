package org.keysupport.bc.scvp.asn1;

import java.util.Vector;

import org.bouncycastle.asn1.ASN1Object;

public class KeyUsages extends SeqOfASN1Object {

	public KeyUsages(Vector<ASN1Object> objs) {
		super(objs);
	}

}
