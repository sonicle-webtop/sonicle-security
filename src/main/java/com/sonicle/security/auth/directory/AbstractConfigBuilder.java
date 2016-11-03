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

import com.sonicle.commons.LangUtils;

/**
 *
 * @author malbinola
 */
public abstract class AbstractConfigBuilder {
	private static final String IS_CASE_SENSITIVE = "isCaseSensitive";
	
	public boolean getIsCaseSensitive(DirectoryOptions opts) {
		return getBoolean(opts, IS_CASE_SENSITIVE, false);
	}
	
	public void setIsCaseSensitive(DirectoryOptions opts, boolean isCaseSensitive) {
		setParam(opts, IS_CASE_SENSITIVE, isCaseSensitive);
	}
	
	protected Object getParam(DirectoryOptions opts, String name) {
		return (opts == null) ? null : opts.getOption(name);
	}
	
	protected void setParam(DirectoryOptions opts, String name, Object value) {
		if(opts != null) opts.setOption(name, value);
	}
	
	protected boolean hasParam(DirectoryOptions opts, String name) {
		return (opts != null) && opts.hasOption(name);
	}
	
	protected String getString(DirectoryOptions opts, String name, String defaultValue) {
		String value = (String)getParam(opts, name);
		return LangUtils.value(value, defaultValue);
	}
	
	protected Boolean getBoolean(DirectoryOptions opts, String name, Boolean defaultValue) {
		Boolean value = (Boolean) getParam(opts, name);
		return LangUtils.value(value, defaultValue);
	}
	
	protected boolean getBoolean(DirectoryOptions opts, String name, boolean defaultValue) {
		return getBoolean(opts, name, (Boolean)defaultValue);
	}
	
	protected Integer getInteger(DirectoryOptions opts, String name, Integer defaultValue) {
		Integer value = (Integer) getParam(opts, name);
		return LangUtils.value(value, defaultValue);
	}
	
	protected int getInteger(DirectoryOptions opts, String name, int defaultValue) {
		return getInteger(opts, name, (Integer)defaultValue);
	}
}
