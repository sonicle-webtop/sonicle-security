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

import com.sonicle.security.Principal;
import com.sonicle.security.auth.DirectoryException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.LdapException;
import org.ldaptive.auth.AuthenticationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author malbinola
 * https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
 */
public class ADDirectory extends AbstractLdapDirectory {
	private final static Logger logger = (Logger)LoggerFactory.getLogger(ADDirectory.class);
	public static final String SCHEME = "ad";

	static final Collection<DirectoryCapability> CAPABILITIES = Collections.unmodifiableCollection(
		EnumSet.of(
			DirectoryCapability.USERS_READ
		)
	);
	
	@Override
	public String getScheme() {
		return SCHEME;
	}
	
	@Override
	public Collection<DirectoryCapability> getCapabilities() {
		return CAPABILITIES;
	}

	@Override
	public ADConfigBuilder getConfigBuilder() {
		return ADConfigBuilder.getInstance();
	}
	
	@Override
	public URI buildUri(String host, Integer port, String path) throws URISyntaxException {
		int iport = (port == null) ? -1 : port;
		return new URI(SCHEME, null, host, iport, path, null, null);
		//int iport = (port == null) ? LdapConfigBuilder.DEFAULT_PORT : port;
		//return new URI(SCHEME, null, host, iport, path, null, null);
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
			ConnectionFactory conFactory = createConnectionFactory(opts, true); // Connection cannot be anonymous
			AuthenticationResponse authResp = ldapAuthenticate(conFactory, userIdField, baseDn, extraFilter, subtree, principal.getUserId(), principal.getPassword(), attrs);
			if(!authResp.getResult()) throw new DirectoryException(authResp.getMessage());
			
			return createUserEntry(opts, authResp.getLdapEntry());
			
		} catch(LdapException ex) {
			logger.error("LdapError", ex);
			throw new DirectoryException(ex);
		}
	}
	*/
}
