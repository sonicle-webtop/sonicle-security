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

	private String subject_id = null;
	private String domainId = null;
	private String name = null;
	private String hashedName = null;
	private String fullName = null;
	private String description = null;
	private String password = null;
	private String credential = null;
	private CredentialAlgorithm algorithm = null;
	private AuthenticationDomain ad;
	
	private ArrayList<GroupPrincipal> groups=new ArrayList<>();

	public Principal(String user_id, AuthenticationDomain ad, String desc) {

		if (ad != null) {
			this.ad = ad;
			if (!ad.isAuthCaseSensitive()) {
				user_id = user_id.toLowerCase();
			}
			String dsuffix = "@" + ad.getDomain();
			if (user_id.endsWith(dsuffix)) {
				int ix = user_id.lastIndexOf(dsuffix);
				user_id = user_id.substring(0, ix);
			}
			this.domainId = ad.getIDDomain();
			this.name = user_id + "@" + domainId;
			this.hashedName = DigestUtils.md5Hex(this.name);
			this.fullName = MessageFormat.format("{0}@{1}", user_id, ad.getDomain());
		} else {
			this.name = user_id;
		}
		this.subject_id = user_id;

		this.description = desc;
	}
	
	public String getSubjectId() {
		return subject_id;
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
