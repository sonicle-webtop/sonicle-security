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
import com.sonicle.security.auth.EntryException;
import com.sonicle.security.auth.directory.AbstractDirectory.AuthUser;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.List;

/**
 *
 * @author malbinola
 */
public interface Directory {
	
	Collection<DirectoryCapability> getCapabilities();
	public abstract <T extends AbstractConfigBuilder> T getConfigBuilder();
	public abstract URI buildUri(String host, Integer port, String path) throws URISyntaxException;
	public abstract String sanitizeUsername(DirectoryOptions opts, String username);
	public abstract boolean validateUsername(DirectoryOptions opts, String username);
	public abstract boolean validatePasswordPolicy(DirectoryOptions opts, char[] password);
	public abstract char[] generatePassword(DirectoryOptions opts, boolean passwordPolicy);
	public abstract AuthUser authenticate(DirectoryOptions opts, Principal principal) throws DirectoryException;
	public abstract List<AuthUser> listUsers(DirectoryOptions opts, String domainId) throws DirectoryException;
	public abstract void addUser(DirectoryOptions opts, String domainId, AuthUser entry) throws EntryException, DirectoryException;
	public abstract void updateUser(DirectoryOptions opts, String domainId, AuthUser entry) throws DirectoryException;
	public abstract void updateUserPassword(DirectoryOptions opts, String domainId, String userId, char[] newPassword) throws DirectoryException;
	public abstract void updateUserPassword(DirectoryOptions opts, String domainId, String userId, char[] oldPassword, char[] newPassword) throws EntryException, DirectoryException;
	public abstract void deleteUser(DirectoryOptions opts, String domainId, String userId) throws DirectoryException;
	public abstract List<String> listGroups(DirectoryOptions opts, String domainId) throws DirectoryException;
}
