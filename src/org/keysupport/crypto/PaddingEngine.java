/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * https://github.com/grandamp/KSJavaAPI/
 *
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 *****************************************************************************/

package org.keysupport.crypto;

import java.util.Arrays;

/**
 * A utility class for various padding mechanisms.
 * 
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 */
public class PaddingEngine {

	/**
	 * Method PKCS1v1_5Pad.
	 * 
	 * Padding mechanism defined in PKCS#1 v1.5, as well as:
	 *  <A HREF="http://www.ietf.org/rfc/rfc3447.txt">RFC3447</A>
	 * 
	 * @param message byte[]
	 * @param modsize int
	 * @return byte[]
	 */
	public static byte[] pkcs1v1_5Pad(byte[] message, int modsize) {

		byte[] newMessage = null;
		int messageOffset = 0;
		final byte[] pkcsPadBytes = new byte[] { (byte) 0x00, (byte) 0x01, (byte) 0xFF, (byte) 0x00 };
		
		newMessage = new byte[modsize];
		Arrays.fill(newMessage, pkcsPadBytes[2]);
		System.arraycopy(pkcsPadBytes, 0, newMessage, 0, 2);
		messageOffset = newMessage.length - message.length;
		System.arraycopy(pkcsPadBytes, 3, newMessage, (messageOffset-1), 1);
		System.arraycopy(message, 0, newMessage, messageOffset, message.length);
		return newMessage;
	}
	
}
