/*
 * Principal.java
 *
 * Created on 12 luglio 2006, 15.40
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */
package com.sonicle.security;

import com.sonicle.security.auth.AuthenticationDomain2;
import java.io.Serializable;
import java.text.MessageFormat;
import java.util.*;
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
	private AuthenticationDomain2 authenticationDomain = null;
	private String name = null;
	private String hashedName = null;
	private String domainId = null;
	private String userId = null;
	private char[] password = null;
	private String displayName = null;
	
	public Principal(AuthenticationDomain2 ad, String domainId, String userId, char[] password) {
		this.authenticationDomain = ad;
		this.name = DomainAccount.buildName(domainId, userId);
		this.hashedName = Principal.buildHashedName(this.name);
		this.domainId = domainId;
		this.userId = userId;
		this.password = password;
	}
	
	
	
	
	
	
	
	
	private String description = null;
	
	private String credential = null;
	private CredentialAlgorithm algorithm = null;
	private AuthenticationDomain ad;
	
	private ArrayList<GroupPrincipal> groups=new ArrayList<>();
	
	
	
	
	
	 
	
	
	
	
	
	
	
	
	public Principal(String domainId, String userId) {
		this.domainId = domainId;
		this.userId = userId;
		this.name = DomainAccount.buildName(this.domainId, userId);
		this.hashedName = Principal.buildHashedName(this.name);
	}

	public Principal(String userId, AuthenticationDomain ad, String desc) {

		if (ad != null) {
			this.ad = ad;
			if (!ad.isAuthCaseSensitive()) {
				userId = userId.toLowerCase();
			}
			String dsuffix = "@" + ad.getDomain();
			if (userId.endsWith(dsuffix)) {
				int ix = userId.lastIndexOf(dsuffix);
				userId = userId.substring(0, ix);
			}
			this.domainId = ad.getIDDomain();
			this.name = DomainAccount.buildName(this.domainId, userId);
			this.hashedName = Principal.buildHashedName(this.name);
		} else {
			this.name = userId;
		}
		this.userId = userId;
		this.description = desc;
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
	
	
	
	
	
	
	
	
	
	public String getDescription() {
		return description;
	}

	public void setDescription(String desc) {
		this.description = desc;
	}

	public void setPassword(String password) {
		this.password = password.toCharArray();
	}

	public void setCredential(String credential) {
		this.credential = credential;
	}

	public String getCredential() {
		return credential;
	}

	public void setCredentialAlgorithm(CredentialAlgorithm algorithm) {
		this.algorithm = algorithm;
	}

	public CredentialAlgorithm getCredentialAlgorithm() {
		return algorithm;
	}

//    public void setAuthenticationDomain(AuthenticationDomain ad) {
//        this.ad=ad;
//    }
	public AuthenticationDomain getAuthenticationDomain() {
		return ad;
	}

	public String getHashedName() {
		return this.hashedName;
	}
	
	public void addGroup(GroupPrincipal group) {
		groups.add(group);
	}
	
	public ArrayList<GroupPrincipal> getGroups() {
		return groups;
	}
	
	/*
	public boolean isAdmin() {
		return Principal.isAdmin(getName());
	}
	*/

	public String toString() {
		return "[name='" + getName() + "' - description='" + description + "']";
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
