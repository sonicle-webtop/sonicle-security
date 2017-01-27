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

/**
 *
 * @author malbinola
 */
public class ADConfigBuilder extends AbstractLdapConfigBuilder {
	private static final ADConfigBuilder BUILDER = new ADConfigBuilder();
	public static final String DEFAULT_LOGIN_FILTER = "&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))";
	public static final String DEFAULT_USER_FILTER = "&(objectClass=person)(objectClass=user)";
	public static final String DEFAULT_USER_ID_FIELD = "sAMAccountName";
	public static final String DEFAULT_USER_FIRSTNAME_FIELD = "givenName";
	public static final String DEFAULT_USER_LASTNAME_FIELD = "sn";
	public static final String DEFAULT_USER_DISPLAYNAME_FIELD = "cn";
	
	public static ADConfigBuilder getInstance() {
		return BUILDER;
	}

	@Override
	public String getLoginFilter(DirectoryOptions opts) {
		return getString(opts, PARAM_LOGIN_FILTER, DEFAULT_LOGIN_FILTER);
	}
	
	@Override
	public String getUserFilter(DirectoryOptions opts) {
		return getString(opts, PARAM_USER_FILTER, DEFAULT_USER_FILTER);
	}
	
	@Override
	public String getUserIdField(DirectoryOptions opts) {
		return getString(opts, PARAM_USER_ID_FIELD, DEFAULT_USER_ID_FIELD);
	}
	
	@Override
	public String getUserFirstnameField(DirectoryOptions opts) {
		return getString(opts, PARAM_USER_FIRSTNAME_FIELD, DEFAULT_USER_FIRSTNAME_FIELD);
	}
	
	@Override
	public String getUserLastnameField(DirectoryOptions opts) {
		return getString(opts, PARAM_USER_LASTNAME_FIELD, DEFAULT_USER_LASTNAME_FIELD);
	}
	
	@Override
	public String getUserDisplayNameField(DirectoryOptions opts) {
		return getString(opts, PARAM_USER_DISPLAYNAME_FIELD, DEFAULT_USER_DISPLAYNAME_FIELD);
	}
}
