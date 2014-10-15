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
package com.sonicle.security;

import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author gbulfon
 */
public class AuthenticatorManager {
	
	public final static Logger logger = (Logger) LoggerFactory.getLogger(AuthenticatorManager.class);
	
	public static final String AUTHENTICATORS_DESCRIPTOR_RESOURCE = "META-INF/sonicle-authenticators.xml";
	
	private static AuthenticatorManager instance=null;
	
	private HashMap<String, String> authenticators = new HashMap<>();
	
	private AuthenticatorManager() {
		System.out.println("***********************************************");
		logger.debug("Initializing AuhenticatorManager");
		ClassLoader cl = Thread.currentThread().getContextClassLoader();
		if (cl == null) cl = AuthenticatorManager.class.getClassLoader();
		Enumeration<URL> enumResources = null;
		try {
			enumResources = cl.getResources(AUTHENTICATORS_DESCRIPTOR_RESOURCE);

			while(enumResources.hasMoreElements()) {
				URL url = enumResources.nextElement();
				XMLConfiguration config = new XMLConfiguration(url);
				logger.debug("Found configuration {}",url);
				List<HierarchicalConfiguration> elAuthenticators = config.configurationsAt("authenticator");
				for(HierarchicalConfiguration elAuthenticator : elAuthenticators) {
					try {
						String schema=elAuthenticator.getString("[@schema]");
						String className=(String)elAuthenticator.getString("[@className]");
						authenticators.put(schema, className);
						logger.debug("Registered authenticator {}={}",schema,className);
					} catch(Exception ex) {
						logger.warn("Authenticator descriptor skipped. Cause: {}", ex.getMessage());
					}
				}
			}				
		} catch(Exception exc) {
			logger.error("Error loading authenticators manifests",exc);
		}
	}
	
	public static synchronized AuthenticatorManager getInstance() {
		if (instance==null) {
			instance=new AuthenticatorManager();
		}
		return instance;
	}
	
	public static String getAuthenticatorClassName(String schema) {
		return getInstance().authenticators.get(schema);
	}
	
}
