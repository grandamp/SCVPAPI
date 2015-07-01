package org.keysupport.bc.scvp.asn1;

import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

public abstract class SeqOfASN1Object extends ASN1Object {

	private Vector<ASN1Object> objs = null;
	
	public SeqOfASN1Object(Vector<ASN1Object> objs) {
		this.objs = objs;
	}

	public SeqOfASN1Object() {
		objs = new Vector<ASN1Object>();
	}

	public void addObj(ASN1Object obj) {
		this.objs.add(obj);
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		for (ASN1Object obj : objs) {
			v.add(obj);
		}
		return new DERSequence(v);
	}

}
