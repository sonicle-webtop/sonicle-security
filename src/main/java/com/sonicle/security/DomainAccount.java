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
package com.sonicle.security;

import java.text.MessageFormat;
import net.sf.qualitycheck.Check;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/**
 *
 * @author malbinola
 */
public class DomainAccount {
	private String domain;
	private String user;
	
	public DomainAccount() {
		this.domain = "";
		this.user = "";
	}

	public DomainAccount(String accountName) {
		int at = StringUtils.lastIndexOf(accountName, "@");
		if(at == -1) throw new UnsupportedOperationException(MessageFormat.format("Unable to parse specified account name {0}", accountName));
		this.domain = StringUtils.substring(accountName, at+1);
		this.user = StringUtils.substring(accountName, 0, at);
	}

	public DomainAccount(String domain, String user) {
		this.domain = Check.notNull(domain);
		this.user = Check.notNull(user);
	}
	
	public String getName() {
		return DomainAccount.buildName(domain, user);
	}

	public String getDomain() {
		return domain;
	}
	
	public DomainAccount setDomain(String value) {
		domain = Check.notNull(value);
		return this;
	}

	public String getUser() {
		return user;
	}
	
	public DomainAccount setUser(String value) {
		user = Check.notNull(value);
		return this;
	}
	
	public boolean hasDomain(String domain) {
		return StringUtils.equals(this.domain, domain);
	}

	@Override
	public String toString() {
		return buildName(domain, user);
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder()
			.append(domain)
			.append(user)
			.toHashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if(obj instanceof DomainAccount == false) return false;
		if(this == obj) return true;
		final DomainAccount otherObject = (DomainAccount) obj;
		return new EqualsBuilder()
			.append(domain, otherObject.domain)
			.append(user, otherObject.user)
			.isEquals();
	}
	
	public static String buildName(String domain, String user) {
		return user + "@" + domain;
	}
}
