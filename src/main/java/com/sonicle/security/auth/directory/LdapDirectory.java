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
package com.sonicle.security.auth.directory;

import com.sonicle.commons.RegexUtils;
import com.sonicle.security.Principal;
import com.sonicle.security.auth.DirectoryException;
import com.sonicle.security.auth.EntryException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import org.ldaptive.AddOperation;
import org.ldaptive.AddRequest;
import org.ldaptive.AttributeModification;
import org.ldaptive.AttributeModificationType;
import org.ldaptive.BindConnectionInitializer;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.Credential;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.DeleteOperation;
import org.ldaptive.DeleteRequest;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.ModifyOperation;
import org.ldaptive.ModifyRequest;
import org.ldaptive.ResultCode;
import org.ldaptive.SearchExecutor;
import org.ldaptive.SearchResult;
import org.ldaptive.auth.AuthenticationRequest;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.Authenticator;
import org.ldaptive.auth.BindAuthenticationHandler;
import org.ldaptive.auth.SearchDnResolver;
import org.ldaptive.extended.PasswordModifyOperation;
import org.ldaptive.extended.PasswordModifyRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author malbinola
 */
public class LdapDirectory extends AbstractDirectory {
	private final static Logger logger = (Logger)LoggerFactory.getLogger(LdapDirectory.class);
	public static final Pattern PATTERN_USERNAME = Pattern.compile("^" + RegexUtils.MATCH_USERNAME + "$");
	
	static final Collection<DirectoryCapability> CAPABILITIES = Collections.unmodifiableCollection(
		EnumSet.of(
			DirectoryCapability.PASSWORD_WRITE,
			DirectoryCapability.USERS_READ,
			DirectoryCapability.USERS_WRITE
		)
	);

	@Override
	public LdapConfigBuilder getConfigBuilder() {
		return LdapConfigBuilder.getInstance();
	}
	
	@Override
	public Collection<DirectoryCapability> getCapabilities() {
		return CAPABILITIES;
	}
	
	@Override
	public String sanitizeUsername(DirectoryOptions opts, String username) {
		LdapConfigBuilder builder = getConfigBuilder();
		return builder.getIsCaseSensitive(opts) ? username : StringUtils.lowerCase(username);
	}
	
	@Override
	public boolean validateUsername(DirectoryOptions opts, String username) {
		return PATTERN_USERNAME.matcher(username).matches();
	}
	
	@Override
	public boolean validatePasswordPolicy(DirectoryOptions opts, char[] password) {
		return true;
	}
	
	@Override
	public UserEntry authenticate(DirectoryOptions opts, Principal principal) throws DirectoryException {
		LdapConfigBuilder builder = getConfigBuilder();
		
		try {
			final String[] attrs = new String[]{"uid", "givenName", "sn", "cn", "mail"};
			final String baseDn = builder.getUsersDn(opts) + "," + builder.getBaseDn(opts);
			
			ConnectionFactory conFactory = createConnectionFactory(opts, false);
			AuthenticationResponse authResp = ldapAuthenticate(conFactory, baseDn, principal.getUserId(), principal.getPassword(), attrs);
			if(!authResp.getResult()) throw new DirectoryException(authResp.getMessage());
			
			return createUserEntry(authResp.getLdapEntry());
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	public List<UserEntry> listUsers(DirectoryOptions opts, String domainId) throws DirectoryException {
		LdapConfigBuilder builder = getConfigBuilder();
		ArrayList<UserEntry> entries = new ArrayList<>();
		
		try {
			ensureCapability(DirectoryCapability.USERS_READ);
			final String[] attrs = new String[]{"uid", "givenName", "sn", "cn", "mail"};
			final String baseDn = builder.getUsersDn(opts) + "," + builder.getBaseDn(opts);
			
			ConnectionFactory conFactory = createConnectionFactory(opts, true);
			Collection<LdapEntry> ldEntries = ldapSearch(conFactory, baseDn, "(uid=*)", attrs);
			
			for(LdapEntry ldEntry : ldEntries) {
				entries.add(createUserEntry(ldEntry));
			}
			return entries;
		
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	public void addUser(DirectoryOptions opts, String domainId, UserEntry entry) throws EntryException, DirectoryException {
		LdapConfigBuilder builder = getConfigBuilder();
		
		try {
			ensureCapability(DirectoryCapability.USERS_WRITE);
			if(StringUtils.isBlank(entry.userId)) throw new DirectoryException("Missing value for 'userId'");
			if(StringUtils.isBlank(entry.firstName)) throw new DirectoryException("Missing value for 'firstName'");
			if(StringUtils.isBlank(entry.lastName)) throw new DirectoryException("Missing value for 'lastName'");
			if(StringUtils.isBlank(entry.displayName)) throw new DirectoryException("Missing value for 'displayName'");
			
			String uid = sanitizeUsername(opts, entry.userId);
			
			final String baseDn = builder.getUsersDn(opts) + "," + builder.getBaseDn(opts);
			ConnectionFactory conFactory = createConnectionFactory(opts, true);
			ldapAdd(conFactory, "uid=" + uid + "," + baseDn, createLdapAddAttrs(entry));
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			if(ex.getResultCode().equals(ResultCode.ENTRY_ALREADY_EXISTS)) {
				throw new EntryException(ex);
			} else {
				throw new DirectoryException(ex);
			}
		}
	}
	
	@Override
	public void updateUser(DirectoryOptions opts, String domainId, UserEntry entry) throws DirectoryException {
		LdapConfigBuilder builder = getConfigBuilder();
		
		try {
			ensureCapability(DirectoryCapability.USERS_WRITE);
			if(StringUtils.isBlank(entry.userId)) throw new DirectoryException("Missing value for 'userId'");
			if(StringUtils.isBlank(entry.firstName)) throw new DirectoryException("Missing value for 'firstName'");
			if(StringUtils.isBlank(entry.lastName)) throw new DirectoryException("Missing value for 'lastName'");
			if(StringUtils.isBlank(entry.displayName)) throw new DirectoryException("Missing value for 'displayName'");
			
			String uid = sanitizeUsername(opts, entry.userId);
			
			final String baseDn = builder.getUsersDn(opts) + "," + builder.getBaseDn(opts);
			ConnectionFactory conFactory = createConnectionFactory(opts, true);
			ldapUpdate(conFactory, "uid=" + uid + "," + baseDn, createLdapUpdateMods(entry));
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	public void deleteUser(DirectoryOptions opts, String domainId, String userId) throws DirectoryException {
		LdapConfigBuilder builder = getConfigBuilder();
		
		try {
			ensureCapability(DirectoryCapability.USERS_WRITE);
			String uid = sanitizeUsername(opts, userId);
			
			final String baseDn = builder.getUsersDn(opts) + "," + builder.getBaseDn(opts);
			ConnectionFactory conFactory = createConnectionFactory(opts, true);
			ldapDelete(conFactory, "uid=" + uid + "," + baseDn);
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	public void updateUserPassword(DirectoryOptions opts, String domainId, String userId, char[] newPassword) throws DirectoryException {
		LdapConfigBuilder builder = getConfigBuilder();
		
		try {
			ensureCapability(DirectoryCapability.PASSWORD_WRITE);
			String uid = sanitizeUsername(opts, userId);
			
			final String baseDn = builder.getUsersDn(opts) + "," + builder.getBaseDn(opts);
			ConnectionFactory conFactory = createConnectionFactory(opts, true);
			ldapChangePassword(conFactory, "uid=" + uid + "," + baseDn, newPassword);
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	public void updateUserPassword(DirectoryOptions opts, String domainId, String userId, char[] oldPassword, char[] newPassword) throws DirectoryException {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public List<String> listGroups(DirectoryOptions dopts, String domainId) throws DirectoryException {
		throw new UnsupportedOperationException("Not supported on this directory");
	}
	
	protected List<LdapAttribute> createLdapAddAttrs(UserEntry userEntry) throws DirectoryException {
		ArrayList<LdapAttribute> attrs = new ArrayList<>();
		attrs.add(new LdapAttribute("uid", userEntry.userId));
		attrs.add(new LdapAttribute("givenName", userEntry.firstName));
		attrs.add(new LdapAttribute("sn", userEntry.lastName));
		attrs.add(new LdapAttribute("cn", userEntry.displayName));
		return attrs;
	}
	
	protected List<AttributeModification> createLdapUpdateMods(UserEntry userEntry) throws DirectoryException {
		ArrayList<AttributeModification> mods = new ArrayList<>();
		mods.add(new AttributeModification(AttributeModificationType.REPLACE, new LdapAttribute("givenName", userEntry.firstName)));
		mods.add(new AttributeModification(AttributeModificationType.REPLACE, new LdapAttribute("sn", userEntry.lastName)));
		mods.add(new AttributeModification(AttributeModificationType.REPLACE, new LdapAttribute("cn", userEntry.displayName)));
		return mods;
	}
	
	protected UserEntry createUserEntry(LdapEntry ldapEntry) {
		UserEntry userEntry = new UserEntry();
		userEntry.userId = getEntryAttribute(ldapEntry, "uid");
		userEntry.firstName = getEntryAttribute(ldapEntry, "givenName");
		userEntry.lastName = getEntryAttribute(ldapEntry, "sn");
		userEntry.displayName = getEntryAttribute(ldapEntry, "cn");
		return userEntry;
	}
	
	protected Collection<LdapEntry> ldapSearch(ConnectionFactory conFactory, String baseDn, String filter, String[] returnAttributes) throws LdapException {
		SearchExecutor executor = new SearchExecutor();
		executor.setBaseDn(baseDn);
		SearchResult result = executor.search(conFactory, filter, returnAttributes).getResult();
		return result.getEntries();
	}
	
	protected void ldapAdd(ConnectionFactory conFactory, String dn, Collection<LdapAttribute> attrs) throws LdapException {
		Connection con = null;
		
		try {
			logger.debug("Adding [{}]", dn);
			con = conFactory.getConnection();
			con.open();
			AddOperation opAdd = new AddOperation(con);
			opAdd.execute(new AddRequest(dn, attrs));
		} finally {
			closeQuietly(con);
		}
	}
	
	protected void ldapUpdate(ConnectionFactory conFactory, String dn, Collection<AttributeModification> mods) throws LdapException {
		Connection con = null;
		
		try {
			logger.debug("Modifying [{}]", dn);
			con = conFactory.getConnection();
			con.open();
			ModifyOperation opMod = new ModifyOperation(con);
			opMod.execute(new ModifyRequest(dn, mods.toArray(new AttributeModification[mods.size()])));
		} finally {
			closeQuietly(con);
		}
	}
	
	protected void ldapDelete(ConnectionFactory conFactory, String dn) throws LdapException {
		Connection con = null;
		
		try {
			logger.debug("Deleting [{}]", dn);
			con = conFactory.getConnection();
			con.open();
			DeleteOperation opDelete = new DeleteOperation(con);
			opDelete.execute(new DeleteRequest(dn));
		} finally {
			closeQuietly(con);
		}
	}
	
	protected void ldapChangePassword(ConnectionFactory conFactory, String dn, char[] newPassword) throws LdapException {
		ldapChangePassword(conFactory, dn, null, newPassword);
	}
	
	protected void ldapChangePassword(ConnectionFactory conFactory, String dn, char[] oldPassword, char[] newPassword) throws LdapException {
		Connection con = null;
		
		try {
			logger.debug("Changing password [{}]", dn);
			con = conFactory.getConnection();
			con.open();
			PasswordModifyOperation opPasswordModify = new PasswordModifyOperation(con);
			Credential oldCredential = (oldPassword == null) ? null : new Credential(oldPassword);
			opPasswordModify.execute(new PasswordModifyRequest(dn, oldCredential, new Credential(newPassword)));
		} finally {
			closeQuietly(con);
		}
	}
	
	protected String getEntryAttribute(LdapEntry ldapEntry, String attributeName) {
		LdapAttribute attr = ldapEntry.getAttribute(attributeName);
		return (attr == null) ? null : StringUtils.defaultIfBlank(attr.getStringValue(), null);
	}
	
	protected void closeQuietly(Connection con) {
		if(con != null) con.close();
	}
	
	protected AuthenticationResponse ldapAuthenticate(ConnectionFactory conFactory, String baseDn, String userId, char[] password, String[] returnAttributes) throws LdapException {
		SearchDnResolver dnResolver = new SearchDnResolver(conFactory);
		dnResolver.setBaseDn(baseDn);
		dnResolver.setUserFilter("uid={user}");
		Authenticator auth = new Authenticator(dnResolver, new BindAuthenticationHandler(conFactory));
		return auth.authenticate(new AuthenticationRequest(userId, new Credential(password), returnAttributes));
	}
	
	protected ConnectionConfig createConnectionConfig(DirectoryOptions opts) {
		return createConnectionConfig(opts, false);
	}
	
	protected ConnectionConfig createConnectionConfig(DirectoryOptions opts, boolean useAdminCredentials) {
		LdapConfigBuilder builder = getConfigBuilder();
		String adminDn = null;
		if(useAdminCredentials) {
			adminDn = "cn=" + builder.getAdminUsername(opts) + "," + builder.getBaseDn(opts);
		}
		char[] adminPassword = useAdminCredentials ? builder.getAdminPassword(opts) : null;
		return createConnectionConfig(builder.getHost(opts), builder.getPort(opts), builder.getUseSSL(opts), builder.getUseStartTLS(opts), adminDn, adminPassword);
	}
	
	protected ConnectionConfig createConnectionConfig(String host, int port, boolean useSSL, boolean useStartTLS, String adminDn, char[] adminPassword) {
		ConnectionConfig config = new ConnectionConfig("ldap://" + host + ":" + port);
		if(useSSL) config.setUseSSL(true);
		if(useStartTLS) config.setUseStartTLS(true);
		if(!StringUtils.isBlank(adminDn) && (adminPassword != null)) {
			config.setConnectionInitializer(new BindConnectionInitializer(adminDn, new Credential(adminPassword)));
		}
		return config;
	}
	
	protected ConnectionFactory createConnectionFactory(DirectoryOptions opts, boolean useAdminCredentials) {
		ConnectionConfig config = createConnectionConfig(opts, useAdminCredentials);
		return new DefaultConnectionFactory(config);
	}
}
