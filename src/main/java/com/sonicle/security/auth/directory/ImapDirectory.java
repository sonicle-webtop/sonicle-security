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

import com.sonicle.commons.EnumUtils;
import com.sonicle.security.Principal;
import com.sonicle.security.ConnectionSecurity;
import com.sonicle.security.auth.DirectoryException;
import com.sonicle.security.auth.EntryException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Store;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author malbinola
 */
public class ImapDirectory extends AbstractDirectory {
	private final static Logger logger = (Logger)LoggerFactory.getLogger(ImapDirectory.class);
	public static final String SCHEME = "imap";
	
	static final Collection<DirectoryCapability> CAPABILITIES = Collections.EMPTY_LIST;
	
	@Override
	public String getScheme() {
		return SCHEME;
	}
	
	@Override
	public Collection<DirectoryCapability> getCapabilities() {
		return CAPABILITIES;
	}

	@Override
	public ImapConfigBuilder getConfigBuilder() {
		return ImapConfigBuilder.getInstance();
	}

	@Override
	public URI buildUri(String host, Integer port, String path) throws URISyntaxException {
		// path can be ignored!
		int iport = (port == null) ? -1 : port;
		return new URI(SCHEME, null, host, iport, null, null, null);
	}

	@Override
	public String sanitizeUsername(DirectoryOptions opts, String username) {
		ImapConfigBuilder builder = getConfigBuilder();
		return builder.getIsCaseSensitive(opts) ? username : StringUtils.lowerCase(username);
	}

	@Override
	public boolean validateUsername(DirectoryOptions opts, String username) {
		return true;
	}

	@Override
	public int validatePasswordPolicy(DirectoryOptions opts, String username, char[] password) {
		return 0;
	}

	@Override
	public AuthUser authenticate(DirectoryOptions opts, Principal principal) throws DirectoryException {
		Store store = null;
		
		try {
			store = createStore(opts);
			store.connect(principal.getUserId(), new String(principal.getPassword()));
			return new AuthUser(principal.getUserId(), null, null, null, null);
			
		} catch(MessagingException ex) {
			logger.error("ImapError", ex);
			throw new DirectoryException(ex);
		} finally {
			closeQuietly(store);
		}
	}

	@Override
	public List<AuthUser> listUsers(DirectoryOptions opts, String domainId) throws DirectoryException {
		throw new DirectoryException("Capability not supported");
	}

	@Override
	public void addUser(DirectoryOptions opts, String domainId, AuthUser entry) throws EntryException, DirectoryException {
		throw new DirectoryException("Capability not supported");
	}

	@Override
	public void updateUser(DirectoryOptions opts, String domainId, AuthUser entry) throws DirectoryException {
		throw new DirectoryException("Capability not supported");
	}

	@Override
	public void updateUserPassword(DirectoryOptions opts, String domainId, String userId, char[] newPassword) throws DirectoryException {
		throw new DirectoryException("Capability not supported");
	}

	@Override
	public void updateUserPassword(DirectoryOptions opts, String domainId, String userId, char[] oldPassword, char[] newPassword) throws EntryException, DirectoryException {
		throw new DirectoryException("Capability not supported");
	}

	@Override
	public void deleteUser(DirectoryOptions opts, String domainId, String userId) throws DirectoryException {
		throw new DirectoryException("Capability not supported");
	}

	@Override
	public List<String> listGroups(DirectoryOptions opts, String domainId) throws DirectoryException {
		throw new DirectoryException("Capability not supported");
	}
	
	private Store createStore(DirectoryOptions opts) throws NoSuchProviderException {
		ImapConfigBuilder builder = getConfigBuilder();
		//TODO: get external properties from DirectoryOptions
		Properties props = new Properties(System.getProperties());
		String imapProto = EnumUtils.equals(builder.getConnectionSecurity(opts), ConnectionSecurity.SSL) ? "imaps" : "imap";
		
		props.put("mail.store.protocol", imapProto);
		props.put("mail." + imapProto + ".host", builder.getHost(opts));
		if(builder.getPort(opts) != null) {
			props.put("mail." + imapProto + ".port", builder.getPort(opts));
		}
		
		if(EnumUtils.equals(builder.getConnectionSecurity(opts), ConnectionSecurity.STARTTLS)) {
			props.put("mail.imap.starttls.enable", true);
		}
		
		final Session session = Session.getInstance(props, null);
		return session.getStore(imapProto);
	}
	
	private void closeQuietly(Store store) {
		try {
			if(store != null) store.close();
		} catch(MessagingException ex) { /* Do nothing... */ }
	}
}
