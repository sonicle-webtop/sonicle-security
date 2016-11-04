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

import com.sonicle.security.Principal;
import com.sonicle.security.auth.DirectoryException;
import java.util.Collection;
import java.util.List;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.auth.AuthenticationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author malbinola
 */
public class NethLdapDirectory extends LdapDirectory {
	private final static Logger logger = (Logger)LoggerFactory.getLogger(NethLdapDirectory.class);
	
	@Override
	public NethLdapConfigBuilder getConfigBuilder() {
		return NethLdapConfigBuilder.getInstance();
	}

	@Override
	public boolean isReadOnly() {
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
			
			conFactory = createConnectionFactory(opts, true);
			Collection<LdapEntry> entries = ldapSearch(conFactory, baseDn, "(uid=" + principal.getUserId() + ")", attrs);
			if(entries.size() != 1) throw new DirectoryException("Returned entries count must be 1");
			
			for(LdapEntry entry : entries) {
				return createUserEntry(entry);
			}
			return null; // This is not possible! :)
			
		} catch(LdapException ex) {
			throw new DirectoryException(ex);
		}
	}
	
	@Override
	protected List<LdapAttribute> createLdapAddAttrs(UserEntry userEntry) throws DirectoryException {
		List<LdapAttribute> attrs = super.createLdapAddAttrs(userEntry);
		LdapAttribute objectClass = new LdapAttribute("objectClass");
		objectClass.addStringValue("inetOrgPerson", "top");
		attrs.add(objectClass);
		return attrs;
	}
}
