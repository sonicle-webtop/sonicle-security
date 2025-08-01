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

import com.sonicle.commons.LangUtils;
import net.sf.qualitycheck.Check;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/**
 *
 * @author malbinola
 */
public class DomainAccount {
	private final String domain;
	private final String local;
	
	/**
	 * @deprecated Use buildFullyQualifiedName instead
	 */
	@Deprecated public static String buildName(String domain, String user) {
		return user + "@" + domain;
	}
	
	/**
	 * @deprecated Use getLocal instead
	 */
	@Deprecated public String getUser() {
		return local;
	}
	
	/**
	 * @deprecated Use toString instead
	 */
	@Deprecated public String getName() {
		return DomainAccount.buildName(domain, local);
	}

	public DomainAccount(final String fullyQualifiedAccountName) {
		int at = StringUtils.lastIndexOf(fullyQualifiedAccountName, "@");
		if (at == -1) throw new UnsupportedOperationException(LangUtils.formatMessage("Unable to parse specified account name {}", fullyQualifiedAccountName));
		this.domain = StringUtils.substring(fullyQualifiedAccountName, at+1);
		this.local = StringUtils.substring(fullyQualifiedAccountName, 0, at);
	}

	public DomainAccount(final String domain, final String local) {
		this.domain = Check.notNull(domain);
		this.local = Check.notNull(local);
	}

	public String getDomain() {
		return domain;
	}
	
	public String getLocal() {
		return local;
	}
	
	public boolean hasDomain(String domain) {
		return StringUtils.equals(this.domain, domain);
	}

	@Override
	public String toString() {
		return buildFullyQualifiedName(domain, local);
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder()
			.append(domain)
			.append(local)
			.toHashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof DomainAccount == false) return false;
		if (this == obj) return true;
		final DomainAccount otherObject = (DomainAccount) obj;
		return new EqualsBuilder()
			.append(domain, otherObject.domain)
			.append(local, otherObject.local)
			.isEquals();
	}
	
	public static String buildFullyQualifiedName(final String domain, final String local) {
		return Check.notNull(local, "local") + "@" + Check.notNull(domain, "domain");
	}
	
	public static DomainAccount parse(final String fullyQualifiedName) {
		return new DomainAccount(fullyQualifiedName);
	}
	
	public static DomainAccount parseQuietly(final String fullyQualifiedName) {
		try {
			return parse(fullyQualifiedName);
		} catch (Exception ex) {
			return null;
		}
	}
}
