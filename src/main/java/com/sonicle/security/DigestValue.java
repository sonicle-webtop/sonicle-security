/*
 * Copyright (C) 2025 Sonicle S.r.l.
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
 * display the words "Copyright (C) 2025 Sonicle S.r.l.".
 */
package com.sonicle.security;

import com.sonicle.commons.EnumUtils;
import com.sonicle.commons.LangUtils;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import net.sf.qualitycheck.Check;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author malbinola
 */
public class DigestValue {
	private final DigestAlgorithm algorithm;
	private final String prfName; // Name of Pseudo Random Function (PRF) (eg. HMAC-SHA1)
	private final Integer iterations;
	private final byte[] salt;
	private final byte[] digest;
	
	private DigestValue(DigestAlgorithm algorithm, String prfName, Integer iterations, byte[] salt, byte[] digest) {
		this.algorithm = Check.notNull(algorithm, "algorithm");
		this.prfName = prfName;
		this.iterations = iterations;
		this.salt = salt;
		this.digest = digest;
	}
	
	public static DigestValue parse(String value) {
		String algo = StringUtils.substringAfter(StringUtils.substringBefore(value, "}"), "{");
		DigestAlgorithm algorithm = DigestAlgorithm.parse(algo, DigestAlgorithm.PLAIN);
		String prfName = null;
		Integer iterations = null;
		byte[] salt = null;
		byte[] digest = null;
		
		String payload = StringUtils.substringAfter(value, "}");
		if (DigestAlgorithm.PLAIN.equals(algorithm)) {
			digest = payload.getBytes(StandardCharsets.UTF_8);
			
		} else {
			String[] tokens = StringUtils.splitPreserveAllTokens(payload, ":");
			digest = LangUtils.base64Decode(extractToken(tokens, tokens.length -1, "Digest"));
			if (algorithm.isSalted()) {
				salt = LangUtils.base64Decode(extractToken(tokens, tokens.length -2, "Salt"));
			}
			if (algorithm.hasNumOfIterations()) {
				iterations = Integer.valueOf(extractToken(tokens, tokens.length -3, "NumOfIterations"));
			}
			if (algorithm.hasPRFFunction()) {
				prfName = extractToken(tokens, tokens.length -4, "PRF Name");
			}
		}
		
		return new DigestValue(algorithm, prfName, iterations, salt, digest);
	}
	
	/**
	 * Returns the configured DigestAlgorithm enum.
	 * @return 
	 */
	public DigestAlgorithm getAlgorithm() {
		return algorithm;
	}
	
	/**
	 * Returns the name of Pseudo Random Function (PRF), if any.
	 * This name should be evaluated against the configured DigestAlgorithm, 
	 * it can be a compact value like "SHA1" or an extended notation like "HMAC-SHA1".
	 * @return 
	 */
	public String getPRFName() {
		return prfName;
	}
	
	/**
	 * Returns the number of iterations of the hashing algorithm, if any.
	 * @return 
	 */
	public Integer getIterations() {
		return iterations;
	}
	
	/**
	 * Returns the Salt bytes used by the hashing algorithm, if any.
	 * @return 
	 */
	public byte[] getSaltBytes() {
		return salt;
	}
	
	/**
	 * Returns the Salt String used by the hashing algorithm, if any.
	 * @return 
	 */
	public String getSaltString() {
		return this.getSaltString(StandardCharsets.UTF_8);
	}
	
	/**
	 * Returns the Salt String used by the hashing algorithm, using the specified Charset, if any.
	 * @param charset The {@linkplain java.nio.charset.Charset} to be used to decode the bytes.
	 * @return 
	 */
	public String getSaltString(Charset charset) {
		return new String(salt, charset);
	}
	
	/**
	 * Returns the Digest bytes calculated by the hashing algorithm.
	 * @return 
	 */
	public byte[] getDigestBytes() {
		return digest;
	}
	
	/**
	 * Returns the Digest String calculated by the hashing algorithm.
	 * @return 
	 */
	public String getDigestString() {
		return this.getDigestString(StandardCharsets.UTF_8);
	}
	
	/**
	 * Returns the Digest String using the specified Charset.
	 * @param charset The {@linkplain java.nio.charset.Charset} to be used to decode the bytes.
	 * @return 
	 */
	public String getDigestString(Charset charset) {
		return new String(digest, charset);
	}
	
	private static String extractToken(String[] tokens, int tokenIndex, String tokenName) {
		Check.greaterOrEqualThan(0, tokenIndex, "Unable to get " + tokenName + " token at position " + tokenIndex);
		Check.lesserThan(tokens.length, tokenIndex, "Unable to get " + tokenName + " token at position " + tokenIndex);
		return tokens[tokenIndex];
	}
	
	public static String toValue(final DigestAlgorithm algorithm, final byte[] digest, final byte[] salt, final Integer iterations, final String prfName) {
		Check.notNull(algorithm, "algorithm");
		String digestString = DigestAlgorithm.PLAIN.equals(algorithm) ? new String(digest, StandardCharsets.UTF_8) : LangUtils.base64Encode(digest);
		return "{" + EnumUtils.getName(algorithm) + "}" + LangUtils.joinStrings(":", StringUtils.upperCase(prfName), LangUtils.toString(iterations), LangUtils.base64Encode(salt), digestString);
	}
}
