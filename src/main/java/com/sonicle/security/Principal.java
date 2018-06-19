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
	private final AuthenticationDomain authenticationDomain;
	private final boolean impersonated;
	private String name = null;
	private String hashedName = null;
	private String domainId = null;
	private String userId = null;
	private char[] password = null;
	private String displayName = null;
	
	public Principal(AuthenticationDomain ad, boolean impersonated, String domainId, String userId, char[] password) {
		this.authenticationDomain = ad;
		this.impersonated = impersonated;
		this.name = DomainAccount.buildName(domainId, userId);
		this.hashedName = Principal.buildHashedName(this.name);
		this.domainId = domainId;
		this.userId = userId;
		this.password = password;
	}	
	
	public Principal(String domainId, String userId) {
		authenticationDomain = null;
		impersonated = false;
		this.domainId = domainId;
		this.userId = userId;
		this.name = DomainAccount.buildName(this.domainId, userId);
		this.hashedName = Principal.buildHashedName(this.name);
	}

	public AuthenticationDomain getAuthenticationDomain() {
		return authenticationDomain;
	}
	
	public boolean isImpersonated() {
		return impersonated;
	}
	
	public static String buildHashedName(String name) {
		return DigestUtils.md5Hex(name);
	}
	
	public static String buildHashedName(String domainId, String userId) {
		return buildHashedName(DomainAccount.buildName(domainId, userId));
	}
	
	/**
	 * Gets the identifier that uniquely identify a user.
	 * This is a composite field: userId@domainId.
	 * @return The unique identifier.
	 */
	@Override
	public String getName() {
		return name;
	}
	
	/**
	 * Gets the user ID.
	 * Remember that in WebTop platform a user is uniquely recognized using
	 * the composite identifier userId@domainId.
	 * @return The user identifier.
	 */
	public String getUserId() {
		return userId;
	}
	
	/**
	 * Gets the (WebTop) domain ID.
	 * Remember that in WebTop platform a user is uniquely recognized using
	 * the composite identifier userId@domainId.
	 * @return The domain identifier
	 */
	public String getDomainId() {
		return domainId;
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
	
	public char[] getPassword() {
		return password;
	}
	
	public void setPassword(char[] password) {
		this.password = password;
	}
	
	/**
	 * Sets the associated display name.
	 * @param displayName The value of the name.
	 */
	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}
	
	public String getHashedName() {
		return this.hashedName;
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
		if(obj instanceof Principal == false) return false;
		if(this == obj) return true;
		final Principal otherObject = (Principal) obj;
		return new EqualsBuilder()
			.append(name, otherObject.name)
			.isEquals();
	}
	
	public static boolean xisAdmin(String name) {
		return StringUtils.equals(name, "admin@*");
	}
	
	public static boolean xisAdmin(String domainId, String userId) {
		return StringUtils.equals(domainId, "*") && StringUtils.equals(userId, "admin");
	}
}
