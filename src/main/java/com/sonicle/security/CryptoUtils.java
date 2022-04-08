/*
 * Copyright (C) 2022 Sonicle S.r.l.
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
 * display the words "Copyright (C) 2022 Sonicle S.r.l.".
 */
package com.sonicle.security;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import net.sf.qualitycheck.Check;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 * https://howtodoinjava.com/java/java-security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
 * https://mkyong.com/java/java-aes-encryption-and-decryption/
 * https://www.baeldung.com/java-aes-encryption-decryption
 * https://www.ibm.com/docs/en/imdm/12.0?topic=encryption-generating-aes-keys-password	
 * @author malbinola
 */
public class CryptoUtils {
	private static final Logger LOGGER = (Logger)LoggerFactory.getLogger(PasswordUtils.class);	
	
	/*
	public static void main(String args[]) throws Exception {
		//String key128 = hex(generateAESKey(128).getEncoded());
		//String key192 = hex(generateAESKey(192).getEncoded());
		byte[] key256bytes = generateAESKey(256).getEncoded();
		String key256hex = Hex.encodeHexString(key256bytes);
		byte[] k2 = Hex.decodeHex(key256hex.toCharArray());
		
		//String utf8256 = new String(key256bytes, StandardCharsets.UTF_8);
		//String key256hex = hex(key256bytes);
		
		//byte[] keyBytes = Hex.decodeHex(key256hex.toCharArray());
		//String key = new String(keyBytes, StandardCharsets.UTF_8);
		
		String text = "myP$as€£rd";
		String enc1 = encryptAES(text, k2);
		String dec1 = decryptAES(enc1, k2);
		System.out.println(enc1);
	}
	*/
	
	/**
	 * Converts a key object to an hexadecimal String.
	 * @param key A key object.
	 * @return The hex String
	 */
	public static String hex(final SecretKey key) {
		return key != null ? hex(key.getEncoded()) : null;
	}
	
	/**
	 * Converts passed bytes to an hexadecimal String.
	 * @param bytes Some bytes.
	 * @return The hex String
	 */
	public static String hex(final byte[] bytes) {
		return bytes != null ? Hex.encodeHexString(bytes) : null;
	}
	
	/**
	 * Encrypts passed String using AES algorithm within the specified key.
	 * @param s String to encrypt.
	 * @param key The AES key to use.
	 * @return The encrypted String or null in case of errors.
	 */
	public static String encryptAES(final String s, final byte[] key) {
		Check.notNull(key, "key");
		// https://stackoverflow.com/a/52571774
		try {
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			return encrypt(s, "AES/CBC/PKCS5Padding", secretKeySpec, true);
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
			LOGGER.error("AES encrypt failed", ex);
			return null;
		}
	}
	
	/**
	 * Decrypts passed String using AES algorithm within the specified key.
	 * @param s String to decrypt.
	 * @param key The AES key to use.
	 * @return The decrypted String or null in case of errors.
	 */
	public static String decryptAES(final String s, final byte[] key) {
		Check.notNull(key, "key");
		
		try {
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			return decrypt(s, "AES/CBC/PKCS5Padding", secretKeySpec, true);
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
			LOGGER.error("AES decrypt failed", ex);
			return null;
		}
	}
	
	/**
	 * Generates a secretKey suitable for AES from a random number.
	 * @param keysize Length of the key in bits: 128, 192 or 256.
	 * @return The generated key
	 * @throws NoSuchAlgorithmException		
	 */
	public static SecretKey generateAESKey(int keysize) throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(keysize, SecureRandom.getInstanceStrong());
		return keyGen.generateKey();
	}
	
	/**
	 * Generates a secretKey suitable for AES from a password and salt.
	 * @param password The password to use as base.
	 * @param salt Random bytes.
	 * @return The generated key
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException 
	 */
	private static SecretKey generateAESKeyFromPassword(final char[] password, final byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
		return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
	}
	
	/**
	 * Generates a random IV of specified size.
	 * @param blockSize Algorithm's block size.
	 * @return The IV object
	 * @throws NoSuchAlgorithmException 
	 */
	public static IvParameterSpec generateRandomIv(final int blockSize) throws NoSuchAlgorithmException {
		SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
		byte[] bytes = new byte[blockSize];
		randomSecureRandom.nextBytes(bytes);
		return new IvParameterSpec(bytes);
	}
	
	/**
	 * Encrypts a String using specified algorithm and secret key.
	 * @param s String to encrypt.
	 * @param algorithm The crypto algorithm to use.
	 * @param key The secret key to use.
	 * @param generateAndCombineIV Specified if generate a random IV and combine it with encrypted data; `false` to not use IV.
	 * @return The encrypted String
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException 
	 */
	public static String encrypt(final String s, final String algorithm, final SecretKey key, final boolean generateAndCombineIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Check.notNull(algorithm, "algorithm");
		Check.notNull(key, "key");
		if (StringUtils.isBlank(s)) return s;
		
		Cipher cipher = Cipher.getInstance(algorithm);
		if (generateAndCombineIV) {
			// Encrypt data and extract IV from cipher
			IvParameterSpec iv = generateRandomIv(cipher.getBlockSize());
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			byte[] encBytes = cipher.doFinal(s.getBytes(StandardCharsets.UTF_8));
			byte[] ivBytes = cipher.getIV();
			// Combine IV + encrypted data
			byte[] combinedBytes = new byte[ivBytes.length + encBytes.length];
			System.arraycopy(ivBytes, 0, combinedBytes, 0, ivBytes.length);
			System.arraycopy(encBytes, 0, combinedBytes, ivBytes.length, encBytes.length);
			// Encode into base64 and return
			return new String(Base64.getEncoder().encode(combinedBytes));
			
		} else {
			// Encrypt data
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encBytes = cipher.doFinal(s.getBytes(StandardCharsets.UTF_8));
			// Encode into base64 and return
			return new String(Base64.getEncoder().encode(encBytes));
		}
	}
	
	/**
	 * Decrypts a String using specified algorithm and secret key.
	 * @param s The String to decrypt.
	 * @param algorithm The crypto algorithm to use.
	 * @param key The secret key to use.
	 * @param combinedIV Specified if IV is combined within encrypted data, `false` to not use IV.
	 * @return The decrypted String
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException 
	 */
	public static String decrypt(final String s, final String algorithm, final SecretKey key, final boolean combinedIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Check.notNull(algorithm, "algorithm");
		Check.notNull(key, "key");
		if (StringUtils.isBlank(s)) return s;
		
		Cipher cipher = Cipher.getInstance(algorithm);
		if (combinedIV) {
			// Decode from base64
			byte[] combinedBytes = Base64.getDecoder().decode(s);
			// Sepatate IV from encrypted data
			byte[] ivBytes = new byte[cipher.getBlockSize()];
			byte[] encBytes = new byte[combinedBytes.length - ivBytes.length];
			System.arraycopy(combinedBytes, 0, ivBytes, 0, ivBytes.length);
			System.arraycopy(combinedBytes, ivBytes.length, encBytes, 0, encBytes.length);
			// Decrypt data and return
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
			byte[] decBytes = cipher.doFinal(encBytes);
			return new String(decBytes, StandardCharsets.UTF_8);
			
		} else {
			// Decode from base64
			byte[] encBytes = Base64.getDecoder().decode(s);
			// Decrypt data and return
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] decBytes = cipher.doFinal(encBytes);
			return new String(decBytes, StandardCharsets.UTF_8);
		}
	}
}
