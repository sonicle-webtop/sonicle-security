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
package com.sonicle.security.otp.provider;

import com.sonicle.security.otp.OTPException;
import com.sonicle.security.otp.OTPKey;
import com.sonicle.security.otp.OTPProviderBase;
import com.sonicle.security.otp.ReseedingSecureRandom;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;

/**
 *
 * @author matteo
 */
public class TOTP extends OTPProviderBase {
	
	private static final String RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";
	private static final String RANDOM_NUMBER_ALGORITHM_PROVIDER = "SUN";
	private static final int DEFAULT_SECRET_BITS = 80;
	public static final String DEFAULT_ALGORITHM = "HmacSHA1";
	public static final int DEFAULT_SECRET_KEY_MODULE = 1000 * 1000;
	public static final long DEFAULT_KEY_VALIDATION_INTERVAL = TimeUnit.SECONDS.toMillis(30);
	public static final int MIN_WINDOW = 1;
	public static final int MAX_WINDOW = 17;
	protected AtomicInteger windowSize = new AtomicInteger(3);
	protected ReseedingSecureRandom secureRandom;
	
	protected int getSecretBits() {
		if(this.properties.containsKey("SECRET_BITS")) return (Integer)this.properties.get("SECRET_BITS");
		return DEFAULT_SECRET_BITS;
	}
	
	protected String getAlgorithm() {
		if(this.properties.containsKey("ALGORITHM")) return (String)this.properties.get("ALGORITHM");
		return DEFAULT_ALGORITHM;
	}
	
	protected long getKeyValidationInterval() {
		if(this.properties.containsKey("KEY_VALIDATION_INTERVAL")) return (Long)this.properties.get("KEY_VALIDATION_INTERVAL");
		return DEFAULT_KEY_VALIDATION_INTERVAL;
	}
	
	public TOTP() {
		this.secureRandom = new ReseedingSecureRandom(RANDOM_NUMBER_ALGORITHM, RANDOM_NUMBER_ALGORITHM_PROVIDER);
	}

	@Override
	public String getName() {
		return "TOTP";
	}
	
	public OTPKey generateCredentials() {
		byte[] buffer = new byte[getSecretBits()/8];
		this.secureRandom.nextBytes(buffer);
		
		// Extracting the bytes making up the secret key
		byte[] secretKey = Arrays.copyOf(buffer, getSecretBits()/8);
		String generatedKey = calculateSecretKey(secretKey);
		
		// Generating the verification code at time = 0
		int validationCode = calculateValidationCode(secretKey);
		
		return new OTPKey(generatedKey, String.valueOf(validationCode));
	}
	
	public boolean check(String userCode, String secret) {
		return check(userCode, secret, getWindowSize());
	}
	
	public boolean check(String userCode, String secret, int window) {
		if (userCode == null) return false;
		int iUserCode = Integer.parseInt(userCode);
		if (iUserCode <= 0 || iUserCode >= DEFAULT_SECRET_KEY_MODULE) return false;
		if (secret == null) throw new OTPException("Secret cannot be null.");
		if (window < MIN_WINDOW || window > MAX_WINDOW) throw new OTPException("Invalid window size.");
		return checkCode(getAlgorithm(), secret, iUserCode, new Date().getTime(), window, getKeyValidationInterval());
	}
	
	protected static boolean checkCode(String algorithm, String secret, long code, long tm, int window, long validationInterval) {
		Base32 codec = new Base32();
		byte[] decodedKey = codec.decode(secret);
		
		// convert unix time into a 30 second "window" as specified by the
		// TOTP specification. Using Google's default interval of 30 seconds.
		final long timeWindow = tm/validationInterval;
		
		// Calculating the verification code of the given key in each of the
		// time intervals and returning true if the provided code is equal to
		// one of them.
		for (int i = -((window - 1) / 2); i <= window / 2; ++i) {
			// Calculating the verification code for the current time interval
			long hash = calculateCode(algorithm, decodedKey, timeWindow + i);
			// Checking if the provided code is equal to the calculated one
			if (hash == code) return true;
		}
		return false;
	}	
	
	/**
	 * This method calculates the secret key given a random byte buffer.
	 * 
	 * @param secretKey A random byte buffer.
	 * @return The secret key.
	 */
	protected String calculateSecretKey(byte[] secretKey) {
		Base32 codec = new Base32();
		byte[] encodedKey = codec.encode(secretKey);
		return new String(encodedKey);
	}
	
	/**
	 * This method calculates the validation code at time 0.
	 * 
	 * @param secretKey The secret key to use.
	 * @return The validation code at time 0.
	 */
	protected int calculateValidationCode(byte[] secretKey) {
		return calculateCode(getAlgorithm(), secretKey, 0);
	}
	
	/**
	 * Calculates the verification code of the provided key at the specified
	 * instant of time using the algorithm specified in RFC 6238.
	 * 
	 * @param algorithm The name of the algorithm.
	 * @param key The secret key in binary format.
	 * @param tm The instant of time.
	 * @return The validation code for the provided key at the specified instant of time.
	 */
	protected static int calculateCode(String algorithm, byte[] key, long tm) {
		// Allocating an array of bytes to represent the specified instant of time
		byte[] data = new byte[8];
		long value = tm;
		
		// Converting the instant of time from the long representation to an
		// array of bytes.
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte)value;
		}

		// Building the secret key specification for the HmacSHA1 algorithm.
		SecretKeySpec signKey = new SecretKeySpec(key, algorithm);

		try {
			// Getting an HmacSHA1 algorithm implementation from the JCE.
			Mac mac = Mac.getInstance(algorithm);
			mac.init(signKey);
			byte[] hash = mac.doFinal(data);

			// Building the validation code.
			int offset = hash[20 - 1] & 0xF;

			// We are using a long because Java hasn't got an unsigned integer type.
			long truncatedHash = 0;

			for (int i = 0; i < 4; ++i) {
				//truncatedHash = (truncatedHash * 256) & 0xFFFFFFFF;
				truncatedHash <<= 8;
                // Java bytes are signed but we need an unsigned one:
				// cleaning off all but the LSB.
				truncatedHash |= (hash[offset + i] & 0xFF);
			}

            // Cleaning bits higher than 32nd and calculating the module with the
			// maximum validation code value.
			truncatedHash &= 0x7FFFFFFF;
			truncatedHash %= DEFAULT_SECRET_KEY_MODULE;
			
			return (int) truncatedHash;
			
		} catch (NoSuchAlgorithmException ex) {
			throw new OTPException("The operation cannot be performed now.");
		} catch(InvalidKeyException ex) {
			throw new OTPException("The operation cannot be performed now.");
		}
	}
	
	/**
	 * Get the default window size used by this instance when an explicit value is not specified.
	 * 
	 * @return The current window size.
	 */
	public int getWindowSize() {
		return this.windowSize.get();
	}
	
	/**
	 * Set the default window size used by this instance when an explicit value
	 * is not specified. This is an integer value representing the number of 30
	 * second windows we check during the validation process, to account for
	 * differences between the server and the client clocks.
	 * The bigger the window, the more tolerant we are about clock skews.
	 * 
	 * @param value must be >=1 and <=17.  Other values are ignored
	 */
	public void setWindowSize(int value) {
		if (value >= MIN_WINDOW && value <= MAX_WINDOW) {
			this.windowSize = new AtomicInteger(value);
		} else {
			throw new OTPException(MessageFormat.format("Invalid window size [{0}]", value));
		}
	}
}
