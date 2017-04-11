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
package com.sonicle.security.auth.directory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author malbinola
 */
public final class LdapNethDirectory extends AbstractLdapDirectory {
	private final static Logger logger = (Logger)LoggerFactory.getLogger(LdapNethDirectory.class);
	public static final String SCHEME = "ldapneth";
	
	static final Collection<DirectoryCapability> CAPABILITIES = Collections.unmodifiableCollection(
		EnumSet.of(
			DirectoryCapability.USERS_READ
		)
	);
	
	@Override
	public LdapNethConfigBuilder getConfigBuilder() {
		return LdapNethConfigBuilder.getInstance();
	}
	
	@Override
	public Collection<DirectoryCapability> getCapabilities() {
		return CAPABILITIES;
	}
	
	@Override
	public URI buildUri(String host, Integer port, String path) throws URISyntaxException {
		int iport = (port == null) ? -1 : port;
		return new URI(SCHEME, null, host, iport, path, null, null);
		// path can be ignored!
		//int iport = (port == null) ? LdapNethConfigBuilder.DEFAULT_PORT : port;
		//return new URI(SCHEME, null, host, iport, null, null, null);
	}
	
	/*
	@Override
	public AuthUser authenticate(DirectoryOptions opts, Principal principal) throws DirectoryException {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		
		try {
			final String userIdField = builder.getUserIdField(opts);
			final String baseDn = builder.getLoginDn(opts);
			final String extraFilter = builder.getLoginFilter(opts);
			final boolean subtree = builder.getLoginSubtreeSearch(opts);
			final String[] attrs = createUserReturnAttrs(opts);
			ConnectionFactory conFactory = createConnectionFactory(opts, false);
			AuthenticationResponse authResp = ldapAuthenticate(conFactory, userIdField, baseDn, extraFilter, subtree, principal.getUserId(), principal.getPassword(), attrs);
			if(!authResp.getResult()) throw new DirectoryException(authResp.getMessage());
			
			final String baseDn2 = builder.getLoginDn(opts);
			final String filter = joinFilters(createUserTargetFilter(opts, principal.getUserId()), builder.getUserFilter(opts));
			conFactory = createConnectionFactory(opts, true);
			Collection<LdapEntry> ldEntries = ldapSearch(conFactory, baseDn2, filter, attrs);
			if(ldEntries.size() != 1) throw new DirectoryException("Returned entries count must be 1");
			
			for(LdapEntry entry : ldEntries) {
				return createUserEntry(opts, entry);
			}
			return null; // This is not possible! :)
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	protected List<LdapAttribute> createLdapAddAttrs(DirectoryOptions opts, AuthUser userEntry) throws DirectoryException {
		List<LdapAttribute> attrs = super.createLdapAddAttrs(opts, userEntry);
		LdapAttribute objectClass = new LdapAttribute("objectClass");
		objectClass.addStringValue("inetOrgPerson", "top");
		attrs.add(objectClass);
		return attrs;
	}
	
	protected String createUserFilter(DirectoryOptions opts, String userIdValue) {
		AbstractLdapConfigBuilder builder = getConfigBuilder();
		// Builds a filter string for searching specific user
		return "(" + builder.getUserIdField(opts) + "=" + userIdValue + ")";
	}
	*/
}
