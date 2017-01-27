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

import com.sonicle.security.ConnectionSecurity;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author malbinola
 */
public abstract class AbstractLdapConfigBuilder extends AbstractConfigBuilder {
	protected static final String PARAM_HOST = "host";
	protected static final String PARAM_PORT = "port";
	protected static final String PARAM_CON_SECURITY = "conSecurity";
	protected static final String PARAM_ADMIN_DN = "adminDn";
	protected static final String PARAM_ADMIN_PASSWORD = "adminPassword";
	protected static final String PARAM_LOGIN_DN = "loginDn"; // Base Dn for authentication
	protected static final String PARAM_LOGIN_FILTER = "loginFilter"; // Filter to use during authentication
	protected static final String PARAM_USER_DN = "userDn"; // Base Dn for operations on user
	protected static final String PARAM_USER_FILTER = "userFilter"; // Filter to use during users listing
	protected static final String PARAM_USER_ID_FIELD = "userIdField"; // Name of the id field (usually uid)
	protected static final String PARAM_USER_FIRSTNAME_FIELD = "userFirstnameField"; // Name of the firstname field (usually givenName)
	protected static final String PARAM_USER_LASTNAME_FIELD = "userLastnameField"; // Name of the lastname field (usually sn)
	protected static final String PARAM_USER_DISPLAYNAME_FIELD = "userDisplayNameField"; // Name of the displayName field 1 (usually cn)
	
	public static final String DEFAULT_HOST = "localhost";
	public static final Integer DEFAULT_PORT = 389;
	public static final String DEFAULT_USER_ID_FIELD = "uid";
	
	public String getHost(DirectoryOptions opts) {
		return getString(opts, PARAM_HOST, DEFAULT_HOST);
	}
	
	public void setHost(DirectoryOptions opts, String host) {
		setParam(opts, PARAM_HOST, host);
	}
	
	public int getPort(DirectoryOptions opts) {
		return getInteger(opts, PARAM_PORT, DEFAULT_PORT);
	}
	
	public void setPort(DirectoryOptions opts, int port) {
		if (port > -1) setParam(opts, PARAM_PORT, port);
	}
	
	public ConnectionSecurity getConnectionSecurity(DirectoryOptions opts) {
		return (ConnectionSecurity)getParam(opts, PARAM_CON_SECURITY);
	}
	
	public void setConnectionSecurity(DirectoryOptions opts, ConnectionSecurity conSecurity) {
		setParam(opts, PARAM_CON_SECURITY, conSecurity);
	}
	
	public String getAdminDn(DirectoryOptions opts) {
		return getString(opts, PARAM_ADMIN_DN, null);
	}
	
	public void setAdminDn(DirectoryOptions opts, String userTreeDn) {
		setParam(opts, PARAM_ADMIN_DN, userTreeDn);
	}
	
	public char[] getAdminPassword(DirectoryOptions opts) {
		return (char[]) getParam(opts, PARAM_ADMIN_PASSWORD);
	}
	
	public void setAdminPassword(DirectoryOptions opts, char[] adminPassword) {
		setParam(opts, PARAM_ADMIN_PASSWORD, adminPassword);
	}
	
	public String getLoginDn(DirectoryOptions opts) {
		return getString(opts, PARAM_LOGIN_DN, null);
	}
	
	public void setLoginDn(DirectoryOptions opts, String loginDn) {
		setParam(opts, PARAM_LOGIN_DN, loginDn);
	}
	
	public String getLoginFilter(DirectoryOptions opts) {
		return getString(opts, PARAM_LOGIN_FILTER, null);
	}
	
	public void setLoginFilter(DirectoryOptions opts, String loginFilter) {
		setParam(opts, PARAM_LOGIN_FILTER, loginFilter);
	}
	
	public String getUserDn(DirectoryOptions opts) {
		return getString(opts, PARAM_USER_DN, null);
	}
	
	public void setUserDn(DirectoryOptions opts, String userDn) {
		setParam(opts, PARAM_USER_DN, userDn);
	}
	
	public String getUserFilter(DirectoryOptions opts) {
		return getString(opts, PARAM_USER_FILTER, null);
	}
	
	public void setUserFilter(DirectoryOptions opts, String userFilter) {
		setParam(opts, PARAM_USER_FILTER, userFilter);
	}
	
	public String getUserIdField(DirectoryOptions opts) {
		return getString(opts, PARAM_USER_ID_FIELD, DEFAULT_USER_ID_FIELD);
	}
	
	public void setUserIdField(DirectoryOptions opts, String userIdField) {
		setParam(opts, PARAM_USER_ID_FIELD, userIdField);
	}
	
	public String getUserFirstnameField(DirectoryOptions opts) {
		return getString(opts, PARAM_USER_FIRSTNAME_FIELD, null);
	}
	
	public void setUserFirstnameField(DirectoryOptions opts, String userFirstnameField) {
		setParam(opts, PARAM_USER_FIRSTNAME_FIELD, userFirstnameField);
	}
	
	public String getUserLastnameField(DirectoryOptions opts) {
		return getString(opts, PARAM_USER_LASTNAME_FIELD, null);
	}
	
	public void setUserLastnameField(DirectoryOptions opts, String userLastnameField) {
		setParam(opts, PARAM_USER_LASTNAME_FIELD, userLastnameField);
	}
	
	public String getUserDisplayNameField(DirectoryOptions opts) {
		return getString(opts, PARAM_USER_DISPLAYNAME_FIELD, null);
	}
	
	public void setUserDisplayNameField(DirectoryOptions opts, String userDisplayNameField) {
		setParam(opts, PARAM_USER_DISPLAYNAME_FIELD, userDisplayNameField);
	}
	
	public static String toDn(String internetName) {
		StringBuilder dn = new StringBuilder();
		for (String token : StringUtils.split(internetName, ".")) {
			dn.append(",dc=");
			dn.append(token);
		}
		return StringUtils.substring(dn.toString(), 1);
	}
}
