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
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author malbinola
 * https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
 */
public enum DigestAlgorithm {
	// Clear value, no hash applied
	PLAIN {
		@Override
		public String getAlgorithmName() { return null; }
		
		@Override
		public boolean isSalted() { return false; }
	},
	// MD5 (insecure, do NOT use it for passwords)
	MD5 {
		@Override
		public String getAlgorithmName() { return "MD5"; }
		
		@Override
		public boolean isSalted() { return false; }
	},
	// Salted MD5 (insecure, do NOT use it for passwords)
	SMD5 {
		@Override
		public String getAlgorithmName() { return "MD5"; }
		
		@Override
		public boolean isSalted() { return true; }
	},
	// SHA-1 (almost insecure, do NOT use it for passwords)
	SHA {
		@Override
		public String getAlgorithmName() { return "SHA-1"; }
		
		@Override
		public boolean isSalted() { return false; }
	},
	// Salted SHA-1 (almost insecure, do NOT use it for passwords)
	SSHA {
		@Override
		public String getAlgorithmName() { return "SHA-1"; }
		
		@Override
		public boolean isSalted() { return true; }
	},
	// SHA-256
	SHA256 {
		@Override
		public String getAlgorithmName() { return "SHA-256"; }
		
		@Override
		public boolean isSalted() { return false; }
	},
	// Salted SHA-256
	SSHA256 {
		@Override
		public String getAlgorithmName() { return "SHA-256"; }
		
		@Override
		public boolean isSalted() { return true; }
	},
	// SHA-512
	SHA512 {
		@Override
		public String getAlgorithmName() { return "SHA-512"; }
		
		@Override
		public boolean isSalted() { return false; }
	},
	// Salted SHA-512
	SSHA512 {
		@Override
		public String getAlgorithmName() { return "SHA-512"; }
		
		@Override
		public boolean isSalted() { return true; }
	},
	// PBKDF2
	PBKDF2 {
		@Override
		public String getAlgorithmName() { return "PBKDF2"; }// + PRF
		
		@Override
		public boolean isSalted() { return true; }

		@Override
		public boolean hasPRFFunction() { return true; }
		
		@Override
		public boolean hasNumOfIterations() { return true; }

		@Override
		public String getAlgorithmNamePRFSuffix(final String prf) {
			String upper = StringUtils.upperCase(prf);
			if (StringUtils.equalsAny(prf, "SHA1", "SHA224", "SHA256", "SHA384", "SHA512")) {
				return "WithHmac" + upper;
			}
			return null;
		}
	};
	// bcrypt
	/*
	BCRYPT {
		@Override
		public boolean isSalted() {
			return true;
		}
	},
	*/
	
	public abstract String getAlgorithmName();
	public abstract boolean isSalted();
	
	public boolean hasPRFFunction() {
		return false;
	}
	
	public boolean hasNumOfIterations() {
		return false;
	}
	
	public String getAlgorithmNamePRFSuffix(final String prf) {
		throw new UnsupportedOperationException("Not supported");
	}
	
	public static DigestAlgorithm parse(final String algorithm) {
		return parse(algorithm, null);
	}
	
	public static DigestAlgorithm parse(final String algorithm, final DigestAlgorithm defaultAlgorithm) {
		String upper = StringUtils.upperCase(algorithm);
		DigestAlgorithm da = EnumUtils.forName(upper, DigestAlgorithm.class);
		return (da != null) ? da : defaultAlgorithm;
	}
}
