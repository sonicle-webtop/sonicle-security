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

import com.sonicle.commons.Base58;
import com.sonicle.commons.LangUtils;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import net.sf.qualitycheck.Check;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
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
	private static final Logger LOGGER = (Logger)LoggerFactory.getLogger(CryptoUtils.class);
	public static final int DEFAULT_SALT_SIZE = 128;
	public static final boolean DEFAULT_USE_STRONG_RANDOM = false;
	public static final String DEFAULT_PBKDF2_PRF = "SHA1";
	public static final HashOptions DEFAULT_HASH_OPTIONS = new HashOptions();
	
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
	
		//DigestValue dv1 = new DigestValue("{PBKDF2}sha256:310000:RmFuY3lTYWx0:Tx6ClgRLksY4Hf2Ogbb5HeAa0XJeEtRoMivAXjc3hDk=");
		
		System.out.println("Base58: " + Base58.encode(CryptoUtils.generateRandomBytes(6)));
		System.out.println("Base58: " + Base58.encode(CryptoUtils.generateAESKey(128).getEncoded()));
		System.out.println("Base58: " + Base58.encode(CryptoUtils.generateAESKey(128).getEncoded()));
		System.out.println("Base58: " + Base58.encode(CryptoUtils.generateAESKey(128).getEncoded()));
		System.out.println("Base58: " + Base58.encode(CryptoUtils.generateAESKey(128).getEncoded()));
		System.out.println("hex: " + LangUtils.hexEncode(CryptoUtils.generateAESKey(128).getEncoded()));
		
		
		System.out.println("SHA256: " + DigestValue.parse("pippo").getDigestString());
		
		System.out.println(hash((String)null, DigestAlgorithm.PBKDF2));
		String sha256 = hash("matteo", DigestAlgorithm.SHA256);
		System.out.println("SHA256: " + sha256);
		System.out.println("SHA256 verify: " + verifyDigest("matteo2", sha256));
		String sha512 = hash("matteo", DigestAlgorithm.SHA512);
		System.out.println("SHA512: " + sha512);
		System.out.println("SHA512 verify: " + verifyDigest("matteo3", sha512));
		String pbkdf2_sha1 = hash("matteo", DigestAlgorithm.PBKDF2);
		
		HashOptions opts = new HashOptions()
			.withPseudoRandomFunctionName("SHA256")
			.withNumOfIterations(10000)
			.withSaltSize(128);
		String s16 = CryptoUtils.generateBase64RandomToken(16);
		String s32 = CryptoUtils.generateBase64RandomToken(32);
		String s = CryptoUtils.generateBase64RandomToken(32);
		String pbkdf2_sha256_ = hash(s, DigestAlgorithm.PBKDF2, opts);
		
		System.out.println("PBKDF2-SHA1: " + pbkdf2_sha1);
		System.out.println("PBKDF2-SHA1 verify: " + verifyDigest("matteo3", pbkdf2_sha1));
		String pbkdf2_sha256 = hash("matteo", DigestAlgorithm.PBKDF2, new HashOptions().withPseudoRandomFunctionName("SHA256"));
		System.out.println("PBKDF2-SHA256: " + pbkdf2_sha256);
		System.out.println("PBKDF2-SHA256 verify: " + verifyDigest("matteo", pbkdf2_sha256));
		
		System.out.println("PBKDF2-SHA256: " + hash("matteo", DigestAlgorithm.PBKDF2, new HashOptions().withPseudoRandomFunctionName("SHA256").withDVKeyLength(128)));
	}
	*/
	
	/**
	 * Converts a key object to an hexadecimal String.
	 * A {@code null} input byte array returns {@code null}.
	 * @param key A key object.
	 * @return The hex String
	 */
	public static String hexEncode(final SecretKey key) {
		return key != null ? LangUtils.hexEncode(key.getEncoded()) : null;
	}
	
	/**
	 * Generates a random byteArray of the specified length.
	 * @param size The size in bytes of the byteArray.
	 * @return A byteArray filled by random bytes.
	 * @throws NoSuchAlgorithmException if no algorithm is avaiable
	 */
	public static byte[] generateRandomBytes(final int size) throws NoSuchAlgorithmException {
		return generateRandomBytes(size, false);
	}
	
	/**
	 * Generates a random byteArray of the specified length.
	 * @param size The size in bytes of the byteArray.
	 * @param strongRandom Set to `true` to use a strong instance of the SecureRandom generator.
	 * @return A byteArray filled by random bytes.
	 * @throws NoSuchAlgorithmException if no algorithm is avaiable
	 */
	public static byte[] generateRandomBytes(final int size, final boolean strongRandom) throws NoSuchAlgorithmException {
		SecureRandom random = strongRandom ? SecureRandom.getInstanceStrong() : new SecureRandom();
		byte[] bytes = new byte[size];
		random.nextBytes(bytes);
		return bytes;
	}
	
	/**
	 * Generates a random token starting from a random byteArray of the specified size.
	 * The resulting random material is finally converted in Hex String.
	 *  - 16 bytes -> 32 characters
	 *  - 24 bytes -> 48 characters
	 *  - 32 bytes -> 64 characters
	 * @param size The size in bytes of the intermediate random byteArray.
	 * @return A random token in Hex form.
	 * @throws NoSuchAlgorithmException if no algorithm is avaiable
	 */
	public static String generateHexRandomToken(final int size) throws NoSuchAlgorithmException {
		return LangUtils.hexEncode(CryptoUtils.generateRandomBytes(size));
	}
	
	/**
	 * Generates a random token starting from a random byteArray of the specified size.
	 * The resulting random material is finally converted in Base64URL Sring.
	 *  - 16 bytes -> 22 characters
	 *  - 24 bytes -> 32 characters
	 *  - 32 bytes -> 43 characters
	 * @param size The size in bytes of the intermediate random byteArray.
	 * @return A random token in Base64 form.
	 * @throws NoSuchAlgorithmException if no algorithm is avaiable
	 */
	public static String generateBase64RandomToken(final int size) throws NoSuchAlgorithmException {
		return toBase64String(CryptoUtils.generateRandomBytes(size));
	}
	
	/**
	 * Generates a secretKey suitable for AES from a generated random number.
	 * Random meterial will be generated using "default" RNG algorithm.
	 * @param keysize Length of the key in bits: 128, 192 or 256.
	 * @return The generated key
	 * @throws NoSuchAlgorithmException 
	 */
	public static SecretKey generateAESKey(final int keysize) throws NoSuchAlgorithmException {
		return generateAESKey(keysize, false);
	}
	
	/**
	 * Generates a secretKey suitable for AES from a generated random number.
	 * Note that using a "strong" algorithm may be slow on certain systems (especially on some Linux).
	 * https://tersesystems.com/blog/2015/12/17/the-right-way-to-use-securerandom/
	 * @param keysize Length of the key in bits: 128, 192 or 256.
	 * @param strongRandom Set to `true` to generate the random material using a "strong" algorithm (as indicated by {@code securerandom.strongAlgorithms} property), otherwise the "default" algorithm will be used.
	 * @return The generated key
	 * @throws NoSuchAlgorithmException	
	 */
	public static SecretKey generateAESKey(final int keysize, final boolean strongRandom) throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(keysize, strongRandom ? SecureRandom.getInstanceStrong() : new SecureRandom());
		return keyGen.generateKey();
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
			
		} catch (IllegalArgumentException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
			LOGGER.error("AES decrypt failed", ex);
			return null;
		}
	}
	
	/**
	 * Generates a secretKey suitable for AES from a password and salt.
	 * @param password The password to use as base.
	 * @param salt Random bytes.
	 * @return The generated key
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException 
	 */
	@Deprecated private static SecretKey generateAESKeyFromPassword(final char[] password, final byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
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
	 * @throws IllegalArgumentException if base64 decode fails
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException 
	 */
	public static String decrypt(final String s, final String algorithm, final SecretKey key, final boolean combinedIV) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
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
	
	public static InputStream decryptP7M(InputStream is) throws Exception {
		try {
			ASN1InputStream asn1InputStream = new ASN1InputStream(is);
			ASN1Primitive asn1Primitive = asn1InputStream.readObject();
			CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asn1Primitive));
			return ((CMSProcessableByteArray)cmsSignedData.getSignedContent()).getInputStream();
		} catch(Exception exc) {
			throw exc;
		}
	}
	
	/**
	 * Generates a random Salt of 128 bits (16 bytes), the recommended size for salting passwords.
	 * Note that using a "strong" algorithm may be slow on certain systems (especially on some Linux).
	 * @param strongRandom Set to `true` to generate the random material using a "strong" algorithm (as indicated by {@code securerandom.strongAlgorithms} property), otherwise the "default" algorithm will be used.
	 * @return The generated Salt
	 * @throws NoSuchAlgorithmException 
	 */
	public static byte[] generateSalt(final boolean strongRandom) throws NoSuchAlgorithmException {
		return generateSalt(DEFAULT_SALT_SIZE, strongRandom);
	}
	
	/**
	 * Generates a random Salt of specified size.
	 * Note that using a "strong" algorithm may be slow on certain systems (especially on some Linux).
	 * @param size Length of the salt in bits: 128, 192 or 256.
	 * @param strongRandom Set to `true` to generate the random material using a "strong" algorithm (as indicated by {@code securerandom.strongAlgorithms} property), otherwise the "default" algorithm will be used.
	 * @return The generated Salt
	 * @throws NoSuchAlgorithmException 
	 */
	public static byte[] generateSalt(final int size, final boolean strongRandom) throws NoSuchAlgorithmException {
		Check.greaterThan(0, size, "size");
		SecureRandom random = strongRandom ? SecureRandom.getInstanceStrong() : new SecureRandom();
		byte[] salt = new byte[size / 8];
		random.nextBytes(salt);
		return salt;
	}
	
	/**
	 * Verifies whether the given plain text value matches an expected digest representation.
	 * The `expectedValue` string is parsed to determine the digest algorithm and its parameters (salt, iterations, PRF, etc.).
	 * @param s The plain text value to verify. Null safe.
	 * @param expectedValue The expected digest value in encoded form. Must not be empty.
	 * @return `true` if the value matches the expected digest, `false` otherwise
	 */
	public static boolean verifyDigest(final String s, final String expectedValue) {
		if (s == null) return false;
		Check.notEmpty(expectedValue, "expectedValue");
		
		DigestValue parsed = DigestValue.parse(expectedValue);
		DigestAlgorithm algorithm = parsed.getAlgorithm();
		if (DigestAlgorithm.PLAIN.equals(algorithm)) {
			return s.equals(parsed.getDigestString());
			
		} else {
			byte[] digest = null;
			try {
				if (DigestAlgorithm.PBKDF2.equals(algorithm)) {
					int dvKeyLength = parsed.getDigestBytes().length * 8;
					digest = generatePBKDF2Secret(s.toCharArray(), algorithm.getAlgorithmNamePRFSuffix(parsed.getPRFName()), parsed.getSaltBytes(), parsed.getIterations(), dvKeyLength);
					
				} else {
					digest = generateDigest(s.toCharArray(), algorithm.getAlgorithmName(), parsed.getSaltBytes());
				}
				
			} catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
				LOGGER.error("Digest computation failed", ex);
				return false;
			}
			
			return byteArraysEquals(parsed.getDigestBytes(), digest);
		}
	}
	
	/**
	 * Verifies whether the given plain text value matches an expected Mac digest representation.
	 * @param s The plain text value to verify. Null safe.
	 * @param expectedValue The expected Mac digest (es. signature). Must not be empty.
	 * @param algorithm The MAC algorithm.
	 * @param secretKey The Mac secret key.
	 * @return `true` if the value matches the expected digest, `false` otherwise
	 */
	public static boolean verifyMac(final String s, final String expectedValue, final MacAlgorithm algorithm, final byte[] secretKey) {
		if (s == null) return false;
		Check.notEmpty(expectedValue, "expectedValue");
		Check.notNull(algorithm, "algorithm");
		Check.notNull(secretKey, "secretKey");
		
		MacValue parsed = MacValue.parse(algorithm, expectedValue);
		if (MacAlgorithm.PLAIN.equals(algorithm)) {
			return s.equals(parsed.getMacString());
			
		} else {
			byte[] mac = null;
			try {
				mac = generateMac(s.toCharArray(), algorithm.getAlgorithmName(), secretKey);
				
			} catch (NoSuchAlgorithmException | InvalidKeyException ex) {
				LOGGER.error("Mac computation failed", ex);
				return false;
			}
			
			return byteArraysEquals(parsed.getMacBytes(), mac);
		}
	}
	
	/**
	 * Computes a digest for the given string using the specified algorithm and default options.
	 * @param s The input string. Null safe.
	 * @param algorithm The digest algorithm to use.
	 * @return the encoded digest value, or null
	 */
	public static String hash(final String s, final DigestAlgorithm algorithm) {
		return hash(s != null ? s.toCharArray() : null, algorithm, DEFAULT_HASH_OPTIONS);
	}
	
	/**
	 * Computes a digest for the given string using the specified algorithm and default options.
	 * @param s The input string. Null safe.
	 * @param algorithm The digest algorithm to use.
	 * @param options Hashing options such as salt size, iterations and PRF.
	 * @return the encoded digest value, or null
	 */
	public static String hash(final String s, final DigestAlgorithm algorithm, final HashOptions options) {
		return hash(s != null ? s.toCharArray() : null, algorithm, options);
	}
	
	/**
	 * Computes a digest for the given character array using the specified algorithm and default options.
	 * @param s The input value as character array. Null safe.
	 * @param algorithm The digest algorithm to use.
	 * @return the encoded digest value, or null
	 */
	public static String hash(final char[] s, final DigestAlgorithm algorithm) {
		return hash(s, algorithm, DEFAULT_HASH_OPTIONS);
	}
	
	/**
	 * Computes a digest for the given character array using the specified algorithm and hashing options.
	 * @param s The input value as character array. Null safe.
	 * @param algorithm The digest algorithm to use.
	 * @param options Hashing options such as salt size, iterations and PRF.
	 * @return the encoded digest value, or null
	 */
	public static String hash(final char[] s, final DigestAlgorithm algorithm, final HashOptions options) {
		if (s == null) return null;
		Check.notNull(algorithm, "algorithm");
		
		if (DigestAlgorithm.PLAIN.equals(algorithm)) {
			return DigestValue.print(algorithm, toByteArray(s), null, null, null, false);
			
		} else {
			try {
				if (DigestAlgorithm.PBKDF2.equals(algorithm)) {
					final String prf = StringUtils.defaultIfBlank(options.prfName, DEFAULT_PBKDF2_PRF);
					int dvKeyLength = returnPBKDF2KeyLength(options.dvKeyLength, prf);
					byte[] salt = generateSalt(options.saltSize, options.useStrongRandom);
					byte[] digest = generatePBKDF2Secret(s, algorithm.getAlgorithmNamePRFSuffix(prf), salt, options.numOfIterations, dvKeyLength);
					return DigestValue.print(algorithm, digest, salt, options.numOfIterations, prf, false);
					
				} else {
					byte[] salt = null;
					if (algorithm.isSalted()) salt = generateSalt(options.saltSize, options.useStrongRandom);
					byte[] digest = generateDigest(s, algorithm.getAlgorithmName(), salt);
					return DigestValue.print(algorithm, digest, salt, null, null, false);
				}
			} catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
				LOGGER.error("Digest computation failed", ex);
				return null;
			}
		}
	}
	
	/**
	 * Computes a digest for the given character array using the specified algorithm and hashing options.
	 * @param s The input value as character array. Null safe.
	 * @param algorithm The digest algorithm to use.
	 * @param secretKey The secretKey to 
	 * @return the encoded digest value, or null
	 */
	public static String computeMac(final char[] s, final MacAlgorithm algorithm, final byte[] secretKey) {
		if (s == null) return null;
		Check.notNull(algorithm, "algorithm");
		Check.notNull(secretKey, "secretKey");
		
		if (MacAlgorithm.PLAIN.equals(algorithm)) {
			return MacValue.print(algorithm, toByteArray(s), true);
			
		} else {
			try {
				byte[] mac = generateMac(s, algorithm.getAlgorithmName(), secretKey);
				return MacValue.print(algorithm, mac, true);

			} catch (NoSuchAlgorithmException | InvalidKeyException ex) {
				LOGGER.error("Mac computation failed", ex);
				return null;
			}
		}
	}
	
	/**
	 * Generates a message digest for the given character array using the specified algorithm.
	 * @param s The input value as a character array. Null safe.
	 * @param algorithm The message digest algorithm.
	 * @return the computed digest as a byte array
	 * @throws NoSuchAlgorithmException 
	 */
	public static byte[] generateDigest(final char[] s, final String algorithm) throws NoSuchAlgorithmException {
		return generateDigest(s, algorithm, null);
	}
	
	/**
	 * Generates a message digest for the given character array using the specified algorithm and an optional salt.
	 * @param s The input value as a character array. Null safe.
	 * @param algorithm The message digest algorithm.
	 * @param salt Optional salt to prepend to the digest computation.
	 * @return the computed digest as a byte array
	 * @throws NoSuchAlgorithmException 
	 */
	public static byte[] generateDigest(final char[] s, final String algorithm, final byte[] salt) throws NoSuchAlgorithmException {
		if (s == null) return null;
		Check.notEmpty(algorithm, "algorithm");
		
		MessageDigest md = MessageDigest.getInstance(algorithm);
		if (salt != null) md.update(salt);
		return md.digest(toByteArray(s));
	}
	
	/**
	 * Returns the specified DV keyLength for PBKDF2 algorithm, 
	 * or a reccommended size depending on the choosen PRF.
	 * @param choosenKeyLength The forced keyLength or NULL.
	 * @param prf The choosen PRF name.
	 * @return 
	 */
	public static int returnPBKDF2KeyLength(final Integer choosenKeyLength, final String prf) {
		if (choosenKeyLength != null) {
			return choosenKeyLength;
		} else {
			if (StringUtils.equalsAny(prf, "SHA224", "SHA256")) return 256;
			else if (StringUtils.equalsAny(prf, "SHA384", "SHA512")) return 512;
			else return 160;
		}
	}
	
	/**
	 * Generates a PBKDF2-derived secret from the given source array.
	 * @param s The source character array. Null safe.
	 * @param algorithmPRFSuffix The PBKDF2 PRF algorithm suffix (e.g. {@code "WithHmacSHA256"}) it is used to build the full algorithm name.
	 * @param salt The salt bytes to use for key derivation.
	 * @param iterations The number of PBKDF2 iterations; must be greater than 0.
	 * @param keyLength The DV key-length to use; must be greater than 0.
	 * @return The digested input as a byte array
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException 
	 */
	public static byte[] generatePBKDF2Secret(final char[] s, final String algorithmPRFSuffix, final byte[] salt, final int iterations, final int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (s == null) return null;
		Check.notNull(salt, "salt");
		Check.greaterThan(0, iterations, "iterations");
		Check.greaterThan(0, keyLength, "keyLength");
		
		KeySpec spec = new PBEKeySpec(s, salt, iterations, keyLength);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2" + algorithmPRFSuffix);
		return factory.generateSecret(spec).getEncoded();
	}
	
	/**
	 * Generates a Mac digest for the given character array using the specified algorithm and key.
	 * @param s The source character array. Null safe.
	 * @param algorithm The Mac digest algorithm.
	 * @param key The secure key.
	 * @return the computed Mac digest as a byte array
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException 
	 */
	public static byte[] generateMac(final char[] s, final String algorithm, final byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		if (s == null) return null;
		Check.notEmpty(algorithm, "algorithm");
		Check.notNull(key, "key");
		
		Mac mac = Mac.getInstance(algorithm);
		mac.init(new SecretKeySpec(key, algorithm));
		return mac.doFinal(toByteArray(s));
	}
	
	public static byte[] toByteArray(final char[] chars) {
		CharBuffer charBuffer = CharBuffer.wrap(chars);
		ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
		byte[] bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
		Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
		return bytes;
	}
	
	public static String toUTF8String(final byte[] bytes) {
		return (bytes == null) ? null : new String(bytes, StandardCharsets.UTF_8);
	}
	
	public static byte[] toUTF8ByteArray(final String s) {
		return (s == null) ? null : s.getBytes(StandardCharsets.UTF_8);
	}
	
	public static byte[] toBase64ByteArray(final String s) {
		return (s == null) ? null : Base64.getUrlDecoder().decode(s);
	}
	
	public static String toBase64String(final byte[] bytes) {
		return (bytes == null) ? null : Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}
	
	private static boolean byteArraysEquals(byte[] ba1, byte[] ba2) {
		int diff = ba1.length ^ ba2.length;
		for (int i = 0; i < ba1.length && i < ba2.length; i++) {
			diff |= ba1[i] ^ ba2[i];
		}
		return diff == 0;
	}
	
	public static class HashOptions {
		private boolean useStrongRandom = DEFAULT_USE_STRONG_RANDOM;
		private boolean encodeOutput = true;
		private int saltSize = DEFAULT_SALT_SIZE;
		private int numOfIterations = 65536; // used for PBKDF2 algo
		private String prfName = null;
		private Integer dvKeyLength = null;
		
		public HashOptions withUseStrongRandom(boolean useStrongRandom) {
			this.useStrongRandom = useStrongRandom;
			return this;
		}
		
		public HashOptions withEncodeOutput(boolean encodeOutput) {
			this.encodeOutput = encodeOutput;
			return this;
		}
		
		public HashOptions withSaltSize(int saltSize) {
			this.saltSize = Check.greaterOrEqualThan(0, saltSize, "saltSize");
			return this;
		}
		
		public HashOptions withNumOfIterations(int numOfIterations) {
			this.numOfIterations = Check.greaterOrEqualThan(0, numOfIterations, "numOfIterations");
			return this;
		}
		
		public HashOptions withPseudoRandomFunctionName(String prfName) {
			this.prfName = StringUtils.upperCase(prfName);
			return this;
		}
		
		public HashOptions withDVKeyLength(int dvKeyLength) {
			this.dvKeyLength = Check.greaterOrEqualThan(0, dvKeyLength, "dvKeyLength");
			return this;
		}
		
		public boolean isUseStrongRandom() {
			return useStrongRandom;
		}
		
		public boolean isEncodeOutput() {
			return encodeOutput;
		}

		public int getSaltSize() {
			return saltSize;
		}

		public int getNumOfIterations() {
			return numOfIterations;
		}
		
		public String getPseudoRandomFunctionName() {
			return prfName;
		}
		
		public int getDVKeyLength() {
			return dvKeyLength;
		}
	}
}
