/*
 * sonicle-security is a helper library developed by Sonicle S.r.l.
 * Copyright (C) 2014 Sonicle S.r.l.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License version 3 as published by
 * the Free Software Foundation with the addition of the following permission
 * added to Section 15 as permitted in Section 7(a): FOR ANY PART OF THE COVERED
 * WORK IN WHICH THE COPYRIGHT IS OWNED BY SONICLE, SONICLE DISCLAIMS THE
 * WARRANTY OF NON INFRINGEMENT OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program; if not, see http://www.gnu.org/licenses or write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA.
 *
 * You can contact Sonicle S.r.l. at email address sonicle@sonicle.com
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License version 3.
 *
 * In accordance with Section 7(b) of the GNU Affero General Public License
 * version 3, these Appropriate Legal Notices must retain the display of the
 * Sonicle logo and Sonicle copyright notice. If the display of the logo is not
 * reasonably feasible for technical reasons, the Appropriate Legal Notices must
 * display the words "Copyright (C) 2014 Sonicle S.r.l.".
 */
package com.sonicle.security.old;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

/**
 *
 * @author malbinola
 */
public class PasswordUtils {
	
	public static String encryptSHA(String string) {
		return new String(new Base64().encode(DigestUtils.sha1(string)));
	}
	
	/*
	public static String encryptSHA(String string) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			md.update(string.getBytes("UTF-8"));
			return new String(new Base64().encode(md.digest()));
			
		} catch(UnsupportedEncodingException | NoSuchAlgorithmException ex) {
			//logger.error("Unable to encrypt", ex);
			return null;
		}
	}
	*/
	
	public static String encryptDES(String string, String key) {
		try {
			DESKeySpec ks = new DESKeySpec(key.getBytes("UTF-8"));
			SecretKey sk = SecretKeyFactory.getInstance("DES").generateSecret(ks);
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, sk);
			return new String(new Base64().encode(cipher.doFinal(string.getBytes("UTF-8"))));
			
		} catch(UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException 
				| InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
			//logger.error("Unable to encrypt", ex);
			return null;
		}
	}
	
	public static String decryptDES(String encString, String key) {
		try {
			DESKeySpec ks = new DESKeySpec(key.getBytes("UTF-8"));
			SecretKey sk = SecretKeyFactory.getInstance("DES").generateSecret(ks);
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.DECRYPT_MODE, sk);
			byte[] dec = new Base64().decode(encString);
			byte[] utf8 = cipher.doFinal(dec);
			return new String(utf8, "UTF-8");
			
		} catch(UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException 
				| InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
			//logger.error("Unable to decrypt", ex);
			return null;
		}
	}
}
