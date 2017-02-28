/* 
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
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program; if not, see http://www.gnu.org/licenses or write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA.
 *
 * You can contact Sonicle S.r.l. at email address sonicle[at]sonicle[dot]com
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
package com.sonicle.security;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.RandomStringUtils;

/**
 *
 * @author malbinola
 */
public class PasswordUtils {
	private static final String LALPHA = "abcdefghijklmnopqrstuvwxyz";
	private static final String UALPHA  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private static final String NUMBERS = "0123456789";
	private static final String SPECIAL = "!@#$%^&*_=+-/";
	
	public static char[] generatePassword(int minLen, int maxLen, int minNoOfLCaseAlpha, int minNoOfUCaseAlpha, int minNoOfDigits, int minNoOfSpecialChars) {
		char[] psw;
		
		if (minLen < maxLen) {
			int rndIndex = new SecureRandom().nextInt((maxLen - minLen)+1) + minLen;
			psw = new char[rndIndex];
		} else {
			psw = new char[minLen];
		}
		
		Map<String, Integer> charGroupsUsed = new HashMap<>();
		charGroupsUsed.put("lalpha", minNoOfLCaseAlpha);
		charGroupsUsed.put("ualpha", minNoOfUCaseAlpha);
		charGroupsUsed.put("numbers", minNoOfDigits);
		charGroupsUsed.put("special", minNoOfSpecialChars);
		int requiredCharactersLeft = minNoOfLCaseAlpha + minNoOfUCaseAlpha + minNoOfDigits + minNoOfSpecialChars;
		
		for (int i = 0; i < psw.length; i++) {
			String selectableChars = "";
			
			// If we still have plenty of characters left to acheive our minimum requirements
			if (requiredCharactersLeft < psw.length - i) {
				// choose from any group at random
				selectableChars = LALPHA + UALPHA + NUMBERS + SPECIAL;
				
			} else { // Choose from a random group that still needs to have a minimum required
				// Choose only from a group that we need to satisfy a minimum for
				for (Map.Entry<String, Integer> charGroup : charGroupsUsed.entrySet()) {
					if ((int) charGroup.getValue() > 0) {
						if ("lcase".equals(charGroup.getKey())) {
							selectableChars += LALPHA;
						} else if ("ualpha".equals(charGroup.getKey())) {
							selectableChars += UALPHA;
						} else if ("numbers".equals(charGroup.getKey())) {
							selectableChars += NUMBERS;
						} else if ("special".equals(charGroup.getKey())) {
							selectableChars += SPECIAL;
						}
					}
				}
			}
			
			// Get the next random character
			char nextChar = RandomStringUtils.random(1, selectableChars).charAt(0);
			psw[i] = nextChar;
			
			// Now figure out where it came from, and decrement the appropriate minimum value.
			String groupUsed = null;
			if (LALPHA.indexOf(nextChar) > -1) {
				groupUsed = "lalpha";
			} else if (UALPHA.indexOf(nextChar) > -1) {
				groupUsed = "ualpha";
			} else if (NUMBERS.indexOf(nextChar) > -1) {
				groupUsed = "numbers";
			} else if (SPECIAL.indexOf(nextChar) > -1) {
				groupUsed = "special";
			}
			charGroupsUsed.put(groupUsed, charGroupsUsed.get(groupUsed) - 1);
			if (charGroupsUsed.get(groupUsed) >= 0) requiredCharactersLeft--;
		}
		
		return psw;
	}
	
	public static String encryptSHA(String string) {
		if(string == null) return null;
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
			
		} catch(IllegalArgumentException | UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException 
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
			
		} catch(IllegalArgumentException | UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException 
				| InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
			//logger.error("Unable to decrypt", ex);
			return null;
		}
	}
}
