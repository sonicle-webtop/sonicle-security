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

	private String user = null;
	private String domainId = null;
	private String name = null;
	private String hashedName = null;
	private String fullName = null;
	private String description = null;
	private String password = null;
	private String credential = null;
	private CredentialAlgorithm algorithm = null;
	private AuthenticationDomain ad;

	public Principal(String user, AuthenticationDomain ad, String desc) {

		if (ad != null) {
			this.ad = ad;
			if (!ad.isAuthCaseSensitive()) {
				user = user.toLowerCase();
			}
			String dsuffix = "@" + ad.getDomain();
			if (user.endsWith(dsuffix)) {
				int ix = user.lastIndexOf(dsuffix);
				user = user.substring(0, ix);
			}
			this.domainId = ad.getIDDomain();
			this.name = user + "@" + domainId;
			this.hashedName = DigestUtils.md5Hex(this.name);
			this.fullName = MessageFormat.format("{0}@{1}", user, ad.getDomain());
		} else {
			this.name = user;
		}
		this.user = user;

		this.description = desc;
	}
	
	public String getUser() {
		return user;
	}

	public String getDomainId() {
		return domainId;
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

	public String getName() {
		return name;
	}

	public String getHashedName() {
		return this.hashedName;
	}

	public String getFullName() {
		return this.fullName;
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
