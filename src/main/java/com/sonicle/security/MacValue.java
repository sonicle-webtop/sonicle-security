/*
 * Copyright (C) 2026 Sonicle S.r.l.
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
 * display the words "Copyright (C) 2026 Sonicle S.r.l.".
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
public class MacValue {
	private final MacAlgorithm algorithm;
	private final byte[] mac;
	
	private MacValue(MacAlgorithm algorithm, byte[] mac) {
		this.algorithm = Check.notNull(algorithm, "algorithm");
		this.mac = mac;
	}
	
	/**
	 * Returns the configured DigestAlgorithm enum.
	 * @return 
	 */
	public MacAlgorithm getAlgorithm() {
		return algorithm;
	}
	
	/**
	 * Returns the Mac bytes calculated by the hashing algorithm.
	 * @return 
	 */
	public byte[] getMacBytes() {
		return mac;
	}
	
	/**
	 * Returns the Mac String using the specified Charset.
	 * @param charset The {@linkplain java.nio.charset.Charset} to be used to decode the bytes.
	 * @return 
	 */
	public String getMacString(Charset charset) {
		return new String(mac, charset);
	}
	
	/**
	 * Returns the Mac String calculated by the hashing algorithm.
	 * @return 
	 */
	public String getMacString() {
		return this.getMacString(StandardCharsets.UTF_8);
	}
	
	public static MacValue parse(final String value) {
		String algo = StringUtils.substringAfter(StringUtils.substringBefore(value, "}"), "{");
		
		MacAlgorithm algorithm;
		String payload;
		if (StringUtils.isBlank(algo)) {
			algorithm = MacAlgorithm.PLAIN;
			payload = value;
		} else {
			algorithm = MacAlgorithm.parse(algo);
			payload = StringUtils.substringAfter(value, "}");
		}
		if (algorithm == null) throw new IllegalArgumentException("Algorithm NOT supported: " + algo);
		
		return parse(algorithm, payload);
	}
	
	public static MacValue parse(final MacAlgorithm algorithm, final String payload) {
		byte[] mac = null;
		if (MacAlgorithm.PLAIN.equals(algorithm)) {
			mac = CryptoUtils.toUTF8ByteArray(payload);
		} else {
			mac = CryptoUtils.toBase64ByteArray(payload);
		}
		
		return new MacValue(algorithm, mac);
	}
	
	/**
	 * Converts the computed Mac bytes into String output.
	 * @param algorithm The Mac algorithm used.
	 * @param mac The computed Mac byte array.
	 * @param rawOutput Set to `true` to return the raw output directly, without algorithm prefix.
	 * @return 
	 */
	public static String print(final MacAlgorithm algorithm, final byte[] mac, final boolean rawOutput) {
		Check.notNull(algorithm, "algorithm");
		String macString = MacAlgorithm.PLAIN.equals(algorithm) ? CryptoUtils.toUTF8String(mac) : CryptoUtils.toBase64String(mac);
		if (rawOutput) {
			return macString;
		} else {
			return "{" + EnumUtils.getName(algorithm) + "}" + macString;
		}
	}
}
