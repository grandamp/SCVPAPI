package org.keysupport.bc.scvp;

import java.io.IOException;


import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.DERUTF8String;
import org.keysupport.bc.scvp.asn1.CVStatusCode;

public class ResponseStatusParser {

	private ASN1SequenceParser _seq;
	private CVStatusCode _statusCode = null;
	private DERUTF8String _errorMessage = null;

	public static ResponseStatusParser getInstance(Object o) throws IOException {
		if (o instanceof ASN1Sequence) {
			return new ResponseStatusParser(((ASN1Sequence) o).parser());
		}
		if (o instanceof ASN1SequenceParser) {
			return new ResponseStatusParser((ASN1SequenceParser) o);
		}
		throw new IOException("unknown object encountered: "
				+ o.getClass().getName());
	}

	private ResponseStatusParser(ASN1SequenceParser seq) throws IOException {
		this._seq = seq;
		this._statusCode = (CVStatusCode)seq.readObject();
		this._errorMessage = (DERUTF8String)seq.readObject();
	}
}
