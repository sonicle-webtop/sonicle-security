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

import com.sonicle.commons.URIBuilder;
import com.sonicle.security.Principal;
import com.sonicle.security.auth.DirectoryException;
import com.sonicle.security.auth.EntryException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemException;
import org.apache.commons.vfs2.FileSystemManager;
import org.apache.commons.vfs2.VFS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author malbinola
 */
public class SmbDirectory extends AbstractDirectory {
	private final static Logger logger = (Logger)LoggerFactory.getLogger(SmbDirectory.class);
	public static final String SCHEME = "smb";
	
	static final Collection<DirectoryCapability> CAPABILITIES = Collections.EMPTY_LIST;
	
	@Override
	public Collection<DirectoryCapability> getCapabilities() {
		return CAPABILITIES;
	}

	@Override
	public SmbConfigBuilder getConfigBuilder() {
		return SmbConfigBuilder.getInstance();
	}

	@Override
	public URI buildUri(String host, Integer port, String path) throws URISyntaxException {
		// path can be ignored!
		int iport = (port == null) ? -1 : port;
		return new URI(SCHEME, null, host, iport, null, null, null);
	}

	@Override
	public String sanitizeUsername(DirectoryOptions opts, String username) {
		SmbConfigBuilder builder = getConfigBuilder();
		return builder.getIsCaseSensitive(opts) ? username : StringUtils.lowerCase(username);
	}

	@Override
	public boolean validateUsername(DirectoryOptions opts, String username) {
		return true;
	}

	@Override
	public boolean validatePasswordPolicy(DirectoryOptions opts, char[] password) {
		return true;
	}

	@Override
	public AuthUser authenticate(DirectoryOptions opts, Principal principal) throws DirectoryException {
		FileObject fo = null;
		
		try {
			FileSystemManager fsm = VFS.getManager();
			logger.debug("Building VFS uri");
			URI uri = createVfsUri(opts, principal);
			logger.debug("Resolving root file [{}, {}:{}]", uri.getScheme(), uri.getHost(), uri.getPort());
			fo = fsm.resolveFile(uri);
			if(!fo.exists()) throw new DirectoryException("Root file not accessible");
			fsm.getFilesCache().clear(fo.getFileSystem());
			return new AuthUser(principal.getUserId(), null, null, null, null);
			
		} catch(FileSystemException | URISyntaxException ex) {
			logger.error("VfsError", ex);
			throw new DirectoryException(ex);
		} finally {
			IOUtils.closeQuietly(fo);
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
	
	private URI createVfsUri(DirectoryOptions opts, Principal principal) throws URISyntaxException {
		return new URIBuilder()
			.setScheme(SCHEME)
			.setHost(getConfigBuilder().getHost(opts))
			.setPort(getConfigBuilder().getPort(opts))
			.setUsername(principal.getUserId())
			.setPassword(new String(principal.getPassword()))
			.setPath("/")
			.build();
	}
}
