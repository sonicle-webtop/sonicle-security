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
import java.text.MessageFormat;
import java.util.*;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * This interface represents the abstract notion of a principal, which can be
 * used to represent any entity, such as an individual, a corporation, and a
 * login id.
 *
 */
public class Principal implements java.security.Principal, Serializable {

	private String domainId = null;
	private String userId = null;
	private String name = null;
	private String hashedName = null;
	private String description = null;
	private String password = null;
	private String credential = null;
	private CredentialAlgorithm algorithm = null;
	private AuthenticationDomain ad;
	
	private ArrayList<GroupPrincipal> groups=new ArrayList<>();

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
			this.name = Principal.buildName(this.domainId, userId);
			this.hashedName = DigestUtils.md5Hex(this.name);
		} else {
			this.name = userId;
		}
		this.userId = userId;
		this.description = desc;
	}
	
	public static String buildName(String domainId, String userId) {
		return userId + "@" + domainId;
	}
	
	/**
	 * Gets the user ID.
	 * Note that in WebTop platform a user is uniquely recognized using
	 * the composite identifier userId@domainId.
	 * @return The user identifier.
	 */
	public String getUserId() {
		return userId;
	}
	
	/**
	 * Gets the (WebTop) domain ID.
	 * Note that in WebTop platform a user is uniquely recognized using
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
		return userId;
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

	public String getDescription() {
		return description;
	}

	public void setDescription(String desc) {
		this.description = desc;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPassword() {
		return password;
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

	public String toString() {
		return "[name='" + getName() + "' - description='" + description + "']";
	}

	public boolean equals(Object o) {
		if (!(o instanceof Principal)) {
			return false;
		}
		return ((Principal) o).getName().equals(name);
	}

}
