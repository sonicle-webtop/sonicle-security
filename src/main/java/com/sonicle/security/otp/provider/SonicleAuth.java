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

import com.sonicle.security.otp.OTPKey;
import com.sonicle.security.otp.OTPProviderBase;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import org.apache.commons.codec.digest.DigestUtils;

/**
 *
 * @author matteo
 */
public class SonicleAuth extends OTPProviderBase {
	public static final long DEFAULT_KEY_VALIDATION_INTERVAL = 60;

	@Override
	public String getName() {
		return "TimeExpire";
	}

	public OTPKey generateCredentials() {
		return generateCredentials("");
	}
	
	public OTPKey generateCredentials(String base) {
		return new OTPKey(String.valueOf(new Date().getTime()), calculateCode(base));
	}
	
	public boolean check(int userCode, int code, long codeTimestamp) {
		return checkCode(userCode, code, codeTimestamp, DEFAULT_KEY_VALIDATION_INTERVAL);
	}
	
	public boolean check(int userCode, int code, long codeTimestamp, long validationInterval) {
		return checkCode(userCode, code, codeTimestamp, validationInterval);
	}
	
	protected static int calculateCode(String base) {
		String hash = DigestUtils.md5Hex(base + String.valueOf(new Date().getTime()));
		return (int)(hash.hashCode() % 1e6);
	}
	
	protected static boolean checkCode(int userCode, int code, long codeTimestamp, long validationInterval) {
		long now = new Date().getTime();
		long msInterval = TimeUnit.SECONDS.toMillis(validationInterval);
		if((now - codeTimestamp) <= msInterval) {
			return String.valueOf(userCode).equals(String.valueOf(code));
		} else {
			return false;
		}
	}
}
