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

import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author malbinola
 */
public class LdapConfigBuilder extends AbstractConfigBuilder {
	private static final LdapConfigBuilder BUILDER = new LdapConfigBuilder();
	protected static final String HOST = "host";
	protected static final String PORT = "port";
	protected static final String USE_SSL = "useSSL";
	protected static final String USE_START_TLS = "useStartTLS";
	protected static final String BASE_DN = "baseDn";
	protected static final String USERS_DN = "";
	protected static final String ADMIN_USERNAME = "adminUsername";
	protected static final String ADMIN_PASSWORD = "adminPassword";
	
	public static LdapConfigBuilder getInstance() {
		return BUILDER;
	}
	
	public String getHost(DirectoryOptions opts) {
		return getString(opts, HOST, null);
	}
	
	public void setHost(DirectoryOptions opts, String host) {
		setParam(opts, HOST, host);
	}
	
	public int getPort(DirectoryOptions opts) {
		return getInteger(opts, PORT, -1);
	}
	
	public void setPort(DirectoryOptions opts, int port) {
		if(port > -1) setParam(opts, PORT, port);
	}
	
	public boolean getUseSSL(DirectoryOptions opts) {
		return getBoolean(opts, USE_SSL, false);
	}
	
	public void setUseSSL(DirectoryOptions opts, boolean useSSL) {
		setParam(opts, USE_SSL, useSSL);
	}
	
	public boolean getUseStartTLS(DirectoryOptions opts) {
		return getBoolean(opts, USE_START_TLS, false);
	}
	
	public void setUseStartTLS(DirectoryOptions opts, boolean useStartTLS) {
		setParam(opts, USE_START_TLS, useStartTLS);
	}
	
	public String getBaseDn(DirectoryOptions opts) {
		return getString(opts, BASE_DN, null);
	}
	
	public void setBaseDn(DirectoryOptions opts, String baseDn) {
		setParam(opts, BASE_DN, baseDn);
	}
	
	public String getUsersDn(DirectoryOptions opts) {
		return getString(opts, USERS_DN, null);
	}
	
	public void setUsersDn(DirectoryOptions opts, String usersDn) {
		setParam(opts, USERS_DN, usersDn);
	}
	
	public String getAdminUsername(DirectoryOptions opts) {
		return getString(opts, ADMIN_USERNAME, null);
	}
	
	public void setAdminUsername(DirectoryOptions opts, String adminUsername) {
		setParam(opts, ADMIN_USERNAME, adminUsername);
	}
	
	public char[] getAdminPassword(DirectoryOptions opts) {
		return (char[]) getParam(opts, ADMIN_PASSWORD);
	}
	
	public void setAdminPassword(DirectoryOptions opts, char[] adminPassword) {
		setParam(opts, ADMIN_PASSWORD, adminPassword);
	}
	
	public static String toDn(String domainName) {
		StringBuilder dn = new StringBuilder();
		for(String token : StringUtils.split(domainName, ".")) {
			dn.append(",dc=");
			dn.append(token);
		}
		return StringUtils.substring(dn.toString(), 1);
	}
}
