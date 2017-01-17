/*
 * Principal.java
 *
 * Created on 12 luglio 2006, 15.40
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
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
	
	public String toString() {
		return "[name='" + getName() + "' - description='" + displayName + "']";
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
