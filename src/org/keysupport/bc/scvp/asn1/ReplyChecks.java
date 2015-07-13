/**
 * The MIT License (MIT)
 * 
 * Copyright (c) 2008-2015 keysupport.org
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.keysupport.bc.scvp.asn1;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * @author tejohnson
 * 
 * This class is a representation of a ReplyChecks.
 * 
 * <pre>
 *       ReplyChecks ::= SEQUENCE OF ReplyCheck
 * </pre>
 *
 * @version $Revision: 1.0 $
 */
public class ReplyChecks extends ASN1Object {

	/*
	 * Memory representation of this object
	 */
	/**
	 * Field value.
	 */
	private ASN1Sequence value;

	/*
	 * The MIN and MAX size of this object are N/A
	 */
	/**
	 * 
	 * @param replyChecks Enumeration<ReplyCheck>
	 */
	public ReplyChecks(Enumeration<ReplyCheck> replyChecks) {

		final ASN1EncodableVector v;

		v = new ASN1EncodableVector();
		while (replyChecks.hasMoreElements()) {
			v.add(replyChecks.nextElement());
		}
		this.value = new DERSequence(v);

	}

	/**
	 * Constructor for ReplyChecks.
	 * @param value ASN1Sequence
	 * @throws IOException
	 */
	private ReplyChecks(ASN1Sequence value) throws IOException {
		/*
		 * Check all of the elements to ensure they are a ReplyCheck
		 */
		Enumeration<?> rcEnum = value.getObjects();
		while (rcEnum.hasMoreElements()) {
			try {
				ReplyCheck.getInstance(rcEnum.nextElement());
			} catch (IOException e) {
				throw new IOException("Invalid ReplyChecks syntax encountered");
			}
		}
		this.value = value;
	}

	@SuppressWarnings("unused")
	private ReplyChecks() {
		//Hiding the default constructor
	}

	/**
	 * Method getInstance.
	 * @param obj Object
	 * @return ReplyChecks
	 * @throws IOException
	 */
	public static ReplyChecks getInstance(Object obj) throws IOException {
		if (obj instanceof ReplyChecks) {
			return (ReplyChecks) obj;
		} else if (obj instanceof ASN1Sequence) {
			return new ReplyChecks(ASN1Sequence.getInstance(obj));
		} else {
			throw new IOException("Invalid ReplyChecks: " + obj.getClass());
		}
	}

	/**
	 * Method getCheck.
	 * @return Enumeration<ReplyCheck>
	 */
	@SuppressWarnings("unchecked")
	public Enumeration<ReplyCheck> getValues() {
		return this.value.getObjects();
	}

	/**
	 * Method toASN1Primitive.
	 * @return ASN1Primitive
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		return this.value;
	}

}
