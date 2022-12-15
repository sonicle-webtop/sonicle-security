/* 
 * Copyright (C) 2018 Sonicle S.r.l.
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
 * display the words "Copyright (C) 2018 Sonicle S.r.l.".
 */
package com.sonicle.security.auth.directory;

import com.sonicle.commons.EnumUtils;
import com.sonicle.commons.RegexUtils;
import com.sonicle.security.Principal;
import com.sonicle.security.ConnectionSecurity;
import com.sonicle.security.auth.DirectoryException;
import com.sonicle.security.auth.EntryException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;
import net.sf.qualitycheck.Check;
import org.apache.commons.lang3.StringUtils;
import org.ldaptive.AddOperation;
import org.ldaptive.AddRequest;
import org.ldaptive.AttributeModification;
import org.ldaptive.AttributeModificationType;
import org.ldaptive.BindConnectionInitializer;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.ConnectionInitializer;
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
import org.ldaptive.ssl.AllowAnyHostnameVerifier;
import org.ldaptive.ssl.AllowAnyTrustManager;
import org.ldaptive.ssl.SslConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author malbinola
 */
public abstract class AbstractLdapDirectory extends AbstractDirectory {
	private final static Logger logger = (Logger)LoggerFactory.getLogger(LdapDirectory.class);
	public static final Pattern PATTERN_USERNAME = Pattern.compile("^" + RegexUtils.MATCH_USERNAME_CHARS + "$");
	
	@Override
	public String sanitizeUsername(DirectoryOptions opts, String username) {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		return builder.getIsCaseSensitive(opts) ? username : StringUtils.lowerCase(username);
	}
	
	@Override
	public boolean validateUsername(DirectoryOptions opts, String username) {
		return PATTERN_USERNAME.matcher(username).matches();
	}
	
	@Override
	public int validatePasswordPolicy(DirectoryOptions opts, String username, char[] password) {
		return 0;
	}
	
	@Override
	public AuthUser authenticate(DirectoryOptions opts, Principal principal) throws DirectoryException {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		
		try {
			final String userIdField = builder.getUserIdField(opts);
			final String baseDn = builder.getLoginDn(opts);
			final String extraFilter = builder.getLoginFilter(opts);
			final boolean subtree = builder.getLoginSubtreeSearch(opts);
			final String[] attrs = createUserReturnAttrs(opts);
			final boolean anonymous = builder.isAdminAnonymous(opts);
			ConnectionFactory conFactory = createConnectionFactory(opts, !anonymous);
			AuthenticationResponse authResp = ldapAuthenticate(conFactory, userIdField, baseDn, extraFilter, subtree, principal.getUserId(), principal.getPassword(), attrs);
			if(!authResp.getResult()) throw new DirectoryException(authResp.getMessage());
			
			return createUserEntry(opts, authResp.getLdapEntry());
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	public List<AuthUser> listUsers(DirectoryOptions opts, String domainId) throws DirectoryException {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		ArrayList<AuthUser> entries = new ArrayList<>();
		
		try {
			ensureCapability(DirectoryCapability.USERS_READ);
			
			final String baseDn = builder.getUserDn(opts);
			final String filter = joinFilters(createUserSearchFilter(opts), builder.getUserFilter(opts));
			final String[] attrs = createUserReturnAttrs(opts);
			ConnectionFactory conFactory = createConnectionFactory(opts, true);
			Collection<LdapEntry> ldEntries = ldapSearch(conFactory, baseDn, filter, attrs);
			
			for(LdapEntry ldEntry : ldEntries) {
				entries.add(createUserEntry(opts, ldEntry));
			}
			return entries;
		
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	public void addUser(DirectoryOptions opts, String domainId, AuthUser entry) throws EntryException, DirectoryException {
		Check.notNull(opts);
		Check.notNull(entry);
		
		try {
			ensureCapability(DirectoryCapability.USERS_WRITE);
			if(StringUtils.isBlank(entry.userId)) throw new DirectoryException("Missing value for 'userId'");
			if(StringUtils.isBlank(entry.displayName)) throw new DirectoryException("Missing value for 'displayName'");
			if(StringUtils.isBlank(entry.firstName)) throw new DirectoryException("Missing value for 'firstName'");
			if(StringUtils.isBlank(entry.lastName)) throw new DirectoryException("Missing value for 'lastName'");
			String uid = sanitizeUsername(opts, entry.userId);
			
			final String dn = createUserTargetDn(opts, uid);
			ConnectionFactory conFactory = createConnectionFactory(opts, true);
			ldapAdd(conFactory, dn, createLdapAddAttrs(opts, entry));
			
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
	public void updateUser(DirectoryOptions opts, String domainId, AuthUser entry) throws DirectoryException {
		Check.notNull(opts);
		Check.notNull(entry);
		
		try {
			ensureCapability(DirectoryCapability.USERS_WRITE);
			if(StringUtils.isBlank(entry.userId)) throw new DirectoryException("Missing value for 'userId'");
			if(StringUtils.isBlank(entry.firstName)) throw new DirectoryException("Missing value for 'firstName'");
			if(StringUtils.isBlank(entry.lastName)) throw new DirectoryException("Missing value for 'lastName'");
			if(StringUtils.isBlank(entry.displayName)) throw new DirectoryException("Missing value for 'displayName'");
			String uid = sanitizeUsername(opts, entry.userId);
			
			final String dn = createUserTargetDn(opts, uid);
			ConnectionFactory conFactory = createConnectionFactory(opts, true);
			ldapUpdate(conFactory, dn, createLdapUpdateMods(opts, entry));
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	public void deleteUser(DirectoryOptions opts, String domainId, String userId) throws DirectoryException {
		Check.notNull(opts);
		Check.notNull(userId);
		
		try {
			ensureCapability(DirectoryCapability.USERS_WRITE);
			String uid = sanitizeUsername(opts, userId);
			
			final String dn = createUserTargetDn(opts, uid);
			ConnectionFactory conFactory = createConnectionFactory(opts, true);
			ldapDelete(conFactory, dn);
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	public void updateUserPassword(DirectoryOptions opts, String domainId, String userId, char[] newPassword) throws DirectoryException {
		Check.notNull(opts);
		Check.notNull(userId);
		Check.notNull(newPassword);
		
		try {
			ensureCapability(DirectoryCapability.PASSWORD_WRITE);
			String uid = sanitizeUsername(opts, userId);
			
			final String dn = createUserTargetDn(opts, uid);
			ConnectionFactory conFactory = createConnectionFactory(opts, true);
			ldapChangePassword(conFactory, dn, newPassword);
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	public void updateUserPassword(DirectoryOptions opts, String domainId, String userId, char[] oldPassword, char[] newPassword) throws DirectoryException {
		Check.notNull(opts);
		Check.notNull(userId);
		Check.notNull(oldPassword);
		Check.notNull(newPassword);
		
		try {
			ensureCapability(DirectoryCapability.PASSWORD_WRITE);
			String uid = sanitizeUsername(opts, userId);
			
			final String dn = createUserTargetDn(opts, uid);
			ConnectionFactory conFactory = createConnectionFactory(opts, true);
			ldapChangePassword(conFactory, dn, oldPassword, newPassword);
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}

	@Override
	public List<String> listGroups(DirectoryOptions dopts, String domainId) throws DirectoryException {
		throw new UnsupportedOperationException("Not supported on this directory");
	}
	
	protected String[] createUserReturnAttrs(DirectoryOptions opts) {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		if (!StringUtils.isBlank(builder.getUserDisplayNameField(opts))) {
			return new String[]{
				builder.getUserIdField(opts),
				builder.getUserFirstnameField(opts),
				builder.getUserLastnameField(opts),
				builder.getUserDisplayNameField(opts)
			};
		} else {
			return new String[]{
				builder.getUserIdField(opts),
				builder.getUserFirstnameField(opts),
				builder.getUserLastnameField(opts)
			};
		}
	}
	
	protected String createUserSearchFilter(DirectoryOptions opts) {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		return builder.getUserIdField(opts) + "=*";
	}
	
	protected String createUserTargetFilter(DirectoryOptions opts, String userId) {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		return builder.getUserIdField(opts) + "=" + userId;
	}
	
	protected String createUserTargetDn(DirectoryOptions opts, String userId) {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		// Builds a Dn string for targetting a specific user
		// Eg. uid=myuser,ou=people,dc=example,dc=com
		return builder.getUserIdField(opts) + "=" + userId + "," + builder.getUserDn(opts);
	}
	
	protected List<LdapAttribute> createLdapAddAttrs(DirectoryOptions opts, AuthUser userEntry) throws DirectoryException {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		ArrayList<LdapAttribute> attrs = new ArrayList<>();
		attrs.add(new LdapAttribute(builder.getUserIdField(opts), userEntry.userId));
		attrs.add(new LdapAttribute(builder.getUserFirstnameField(opts), userEntry.firstName));
		attrs.add(new LdapAttribute(builder.getUserLastnameField(opts), userEntry.lastName));
		if (!StringUtils.isBlank(builder.getUserDisplayNameField(opts))) {
			attrs.add(new LdapAttribute(builder.getUserDisplayNameField(opts), userEntry.displayName));
		}
		return attrs;
	}
	
	protected List<AttributeModification> createLdapUpdateMods(DirectoryOptions opts, AuthUser userEntry) throws DirectoryException {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		ArrayList<AttributeModification> mods = new ArrayList<>();
		mods.add(new AttributeModification(AttributeModificationType.REPLACE, new LdapAttribute(builder.getUserFirstnameField(opts), userEntry.firstName)));
		mods.add(new AttributeModification(AttributeModificationType.REPLACE, new LdapAttribute(builder.getUserLastnameField(opts), userEntry.lastName)));
		if (!StringUtils.isBlank(builder.getUserDisplayNameField(opts))) {
			mods.add(new AttributeModification(AttributeModificationType.REPLACE, new LdapAttribute(builder.getUserDisplayNameField(opts), userEntry.displayName)));
		}
		return mods;
	}
	
	protected AuthUser createUserEntry(DirectoryOptions opts, LdapEntry ldapEntry) {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		AuthUser userEntry = new AuthUser();
		userEntry.userId = getEntryAttribute(ldapEntry, builder.getUserIdField(opts));
		userEntry.firstName = getEntryAttribute(ldapEntry, builder.getUserFirstnameField(opts));
		userEntry.lastName = getEntryAttribute(ldapEntry, builder.getUserLastnameField(opts));
		if (!StringUtils.isBlank(builder.getUserDisplayNameField(opts))) {
			userEntry.displayName = getEntryAttribute(ldapEntry, builder.getUserDisplayNameField(opts));
		} else if (!StringUtils.isBlank(userEntry.firstName) || !StringUtils.isBlank(userEntry.lastName)) {
			userEntry.displayName = StringUtils.trim(StringUtils.join(userEntry.firstName, " ", userEntry.lastName));
		} else {
			userEntry.displayName = userEntry.userId;
		}
		return userEntry;
	}
	
	protected Collection<LdapEntry> ldapSearch(ConnectionFactory conFactory, String baseDn, String filter, String[] returnAttributes) throws LdapException {
		SearchExecutor executor = new SearchExecutor();
		executor.setBaseDn(baseDn);
		logger.debug("ldapSearch [{baseDn: {}, filter: {}]", baseDn, filter);
		SearchResult result = executor.search(conFactory, filter, returnAttributes).getResult();
		return result.getEntries();
	}
	
	protected void ldapAdd(ConnectionFactory conFactory, String dn, Collection<LdapAttribute> attrs) throws LdapException {
		Connection con = null;
		
		try {
			logger.debug("ldapAdd [{dn: {}", dn);
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
			logger.debug("ldapUpdate [{dn: {}", dn);
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
			logger.debug("ldapDelete [{dn: {}", dn);
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
			logger.debug("ldapChangePassword [{dn: {}", dn);
			con = conFactory.getConnection();
			con.open();
			PasswordModifyOperation opPasswordModify = new PasswordModifyOperation(con);
			Credential oldCredential = (oldPassword == null) ? null : new Credential(oldPassword);
			opPasswordModify.execute(new PasswordModifyRequest(dn, oldCredential, new Credential(newPassword)));
		} finally {
			closeQuietly(con);
		}
	}
	
	protected String joinFilters(String filter1, String filter2) {
		if (StringUtils.isBlank(filter1)) return StringUtils.defaultString(filter2);
		if (StringUtils.isBlank(filter2)) return StringUtils.defaultString(filter1);
		return "(&(" + filter1 + ")(" + filter2 + "))";
	}
	
	protected String getEntryAttribute(LdapEntry ldapEntry, String attributeName) {
		LdapAttribute attr = ldapEntry.getAttribute(attributeName);
		return (attr == null) ? null : StringUtils.defaultIfBlank(attr.getStringValue(), null);
	}
	
	protected void closeQuietly(Connection con) {
		if(con != null) con.close();
	}
	
	protected AuthenticationResponse ldapAuthenticate(ConnectionFactory conFactory, String userIdField, String baseDn, String extraFilter, boolean subtreeSearch, String userId, char[] password, String[] returnAttributes) throws LdapException {
		SearchDnResolver dnResolver = new SearchDnResolver(conFactory);
		dnResolver.setBaseDn(baseDn);
		final String filter = joinFilters(userIdField + "={user}", extraFilter);
		dnResolver.setUserFilter(filter);
		dnResolver.setSubtreeSearch(subtreeSearch);
		logger.debug("ldapAuthenticate [user: {}, baseDn: {}, filter: {}, subtree: {}]", userId, baseDn, filter, subtreeSearch);
		Authenticator auth = new Authenticator(dnResolver, new BindAuthenticationHandler(conFactory));
		return auth.authenticate(new AuthenticationRequest(userId, new Credential(password), returnAttributes));
	}
	
	protected ConnectionFactory createConnectionFactory(DirectoryOptions opts, boolean useAdminCredentials) {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		String dn = useAdminCredentials ? builder.getAdminDn(opts) : null;
		char[] password = useAdminCredentials ? builder.getAdminPassword(opts) : null;
		return createConnectionFactory(opts, dn, password);
	}
	
	protected ConnectionFactory createConnectionFactory(DirectoryOptions opts, String dn, char[] password) {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		ConnectionConfig config = setupConnection(builder.getHost(opts), builder.getPort(opts), builder.getConnectionSecurity(opts), dn, password);
		logConnectionConfig(config);
		return new DefaultConnectionFactory(config);
	}
	
	protected void logConnectionConfig(ConnectionConfig config) {
		ConnectionInitializer ci = config.getConnectionInitializer();
		if (ci instanceof BindConnectionInitializer) {
			logger.debug("Setting-up LDAP connection [url: {}, bindDn: {}]", config.getLdapUrl(), ((BindConnectionInitializer)ci).getBindDn());
		} else {
			logger.debug("Setting-up LDAP connection [url: {}]", config.getLdapUrl());
		}
	}
	
	protected ConnectionConfig setupConnection(String host, int port, ConnectionSecurity security, String dn, char[] password) {
		ConnectionConfig config = new ConnectionConfig("ldap://" + host + ":" + port);
		
		if (EnumUtils.equals(security, ConnectionSecurity.SSL)) {
			SslConfig sslConfig = new SslConfig(new AllowAnyTrustManager());
			sslConfig.setHostnameVerifier(new AllowAnyHostnameVerifier());
			config.setSslConfig(sslConfig);
			config.setLdapUrl("ldaps://" + host + ":" + port);
			config.setUseSSL(true);
		} else if (EnumUtils.equals(security, ConnectionSecurity.STARTTLS)) {
			SslConfig sslConfig = new SslConfig(new AllowAnyTrustManager());
			sslConfig.setHostnameVerifier(new AllowAnyHostnameVerifier());
			config.setSslConfig(sslConfig);
			config.setUseStartTLS(true);
		}
		if(!StringUtils.isBlank(dn) && (password != null)) {
			config.setConnectionInitializer(new BindConnectionInitializer(dn, new Credential(password)));
		}
		return config;
	}
}
