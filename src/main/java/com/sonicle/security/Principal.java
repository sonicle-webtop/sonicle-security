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

import com.sonicle.security.auth.directory.AbstractDirectory;
import java.io.Serializable;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/**
 * This interface represents the abstract notion of a principal, which can be
 * used to represent any entity, such as an individual, a corporation, and a
 * login id.
 *
 */
public class Principal implements java.security.Principal, Serializable {
	private final boolean impersonated;
	private final String name;
	private final String hashedName;
	private char[] password = null;
	private String displayName = null;
	private AbstractDirectory.AuthUser directoryEntry = null;
	
	public Principal(final String domain, final String local) {
		this(false, domain, local, null);
	}
	
	public Principal(final boolean impersonated, final String domain, final String local, final char[] password) {
		this.impersonated = impersonated;
		this.name = DomainAccount.buildFullyQualifiedName(domain, local);
		this.hashedName = Principal.buildHashedName(this.name);
		this.password = password;
	}
	
	public boolean isImpersonated() {
		return impersonated;
	}
	
	/**
	 * Gets the identifier that uniquely identify a user.
	 * This is a composite field: user@domain.
	 * @return The unique identifier.
	 */
	@Override
	public String getName() {
		return name;
	}
	
	/**
	 * Gets the identifier that uniquely identify this principal.
	 * This call is an alias og getName().
	 * @return The unique identifier.
	 */
	public String getID() {
		return getName();
	}
	
	public String getUniqueKey() {
		return this.hashedName;
	}
	
	/**
	 * Gets the user ID.
	 * @return The user local identifier.
	 */
	public String getUserId() {
		return DomainAccount.parse(name).getLocal();
	}
	
	/**
	 * Gets the domain ID.
	 * @return The domain identifier
	 */
	public String getDomainId() {
		return DomainAccount.parse(name).getDomain();
	}
	
	/**
	 * Check if this Principal's domain matches with passed domain ID.
	 * @param domainId The domain ID to check.
	 * @return `true` if matches
	 */
	public boolean hasDomainId(final String domainId) {
		return StringUtils.equals(this.getDomainId(), domainId);
	}
	
	/**
	 * Gets the subject ID for Shiro calls.
	 * This is an alias of getUserId method.
	 * @return The user identifier.
	 */
	public String getSubjectId() {
		return getUserId();
	}
	
	/**
	 * Gets the associated display name.
	 * @return The display name.
	 */
	public String getDisplayName() {
		return displayName;
	}
	
	/**
	 * Sets the associated display name.
	 * @param displayName The value of the name.
	 */
	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}
	
	public char[] getPassword() {
		return password;
	}
	
	public void setPassword(char[] password) {
		this.password = password;
	}
	
	public String toFullyQualifiedUsername(final String domain) {
		return DomainAccount.buildFullyQualifiedName(domain, getUserId());
	}
	
	/**
	 * Returns and clear any authentication result object previously set.
	 * @return 
	 */
	public AbstractDirectory.AuthUser popDirectoryEntry() {
		AbstractDirectory.AuthUser de = this.directoryEntry;
		this.directoryEntry = null;
		return de;
	}
	
	/**
	 * Saves directory authentication result for later.
	 * @param directoryEntry The data object.
	 */
	public void pushDirectoryEntry(AbstractDirectory.AuthUser directoryEntry) {
		this.directoryEntry = directoryEntry;
	}
	
	@Override
	public String toString() {
		return "[name='" + getName() + "' - displayName='" + displayName + "']";
	}
	
	@Override
	public int hashCode() {
		return new HashCodeBuilder()
			.append(name)
			.toHashCode();
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Principal == false) return false;
		if (this == obj) return true;
		final Principal otherObject = (Principal) obj;
		return new EqualsBuilder()
			.append(name, otherObject.name)
			.isEquals();
	}
	
	public static String buildHashedName(String name) {
		return DigestUtils.md5Hex(name);
	}
	
	public static String buildHashedName(String domain, String local) {
		return buildHashedName(DomainAccount.buildFullyQualifiedName(domain, local));
	}
	
	public static boolean xisAdminDomain(String domainId) {
		return StringUtils.equals(domainId, "*");
	}
	
	public static boolean xisAdmin(String profileId) {
		return StringUtils.equals(profileId, "admin@*");
	}
	
	public static boolean xisAdmin(String domainId, String userId) {
		return StringUtils.equals(domainId, "*") && StringUtils.equals(userId, "admin");
	}
}
