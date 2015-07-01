package org.keysupport.bc.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

public abstract class SeqOfASN1Object extends ASN1Object {

	private ASN1EncodableVector objs = null;
	
	public SeqOfASN1Object(ASN1EncodableVector objs) {
		this.objs = objs;
	}

	public SeqOfASN1Object() {
		this.objs = new ASN1EncodableVector();
	}

	public void addObj(ASN1Object obj) {
		this.objs.add(obj);
	}
	
	public void setObj(ASN1EncodableVector objs) {
		this.objs = objs;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return new DERSequence(objs);
	}

}
