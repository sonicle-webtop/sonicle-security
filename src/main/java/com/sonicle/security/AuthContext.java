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

import java.net.URI;
import java.net.URISyntaxException;
import net.sf.qualitycheck.Check;

/**
 *
 * @author malbinola
 */
public class AuthContext {
	private final String domainId;
	private final String internetName;
	private final URI dirUri;
	private final boolean dirCaseSensitive;
	private final String dirAdmin;
	private final char[] dirPassword;
	private final ConnectionSecurity dirConnSecurity;
	private final String dirParameters;
	
	public AuthContext(final String domainId, final String internetName, final String dirUri, final boolean dirCaseSensitive, final String dirAdmin, final char[] dirPassword, final ConnectionSecurity authConSecurity, final String dirParameters) throws URISyntaxException {
		this(domainId, internetName, new URI(dirUri), dirCaseSensitive, dirAdmin, dirPassword, authConSecurity, dirParameters);
	}
	
	public AuthContext(final String domainId, final String internetName, final URI dirUri, final boolean dirCaseSensitive, final String dirAdmin, final char[] dirPassword, final ConnectionSecurity authConSecurity, final String dirParameters) {
		this.domainId = Check.notEmpty(domainId, "domainId");
		this.internetName = internetName;
		this.dirUri = Check.notNull(dirUri, "dirUri");
		this.dirCaseSensitive = dirCaseSensitive;
		this.dirAdmin = dirAdmin;
		this.dirPassword = dirPassword;
		this.dirConnSecurity = authConSecurity;
		this.dirParameters = dirParameters;
	}
	
	public String getDomainId() {
		return domainId;
	}

	public String getInternetName() {
		return internetName;
	}

	public URI getDirUri() {
		return dirUri;
	}
	
	public boolean getDirCaseSensitive() {
		return dirCaseSensitive;
	}

	public String getDirAdmin() {
		return dirAdmin;
	}

	public char[] getDirPassword() {
		return dirPassword;
	}
	
	public ConnectionSecurity getDirConnSecurity() {
		return dirConnSecurity;
	}
	
	public String getDirParameters() {
		return dirParameters;
	}
}
