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
package com.sonicle.security.auth;

import com.sonicle.commons.LangUtils;
import com.sonicle.security.auth.directory.AbstractDirectory;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author malbinola
 */
public class DirectoryManager {
	private final static Logger logger = (Logger)LoggerFactory.getLogger(DirectoryManager.class);
	private static final String CONFIG_RESOURCE = "META-INF/auth-directories.xml";
	private static DirectoryManager instance;
	
	private final HashMap<String, AbstractDirectory> directories = new HashMap<>();
	
	public static synchronized DirectoryManager getManager() {
		if(instance == null) instance = new DirectoryManager();
		return instance;
	}
	
	private DirectoryManager() {
		ClassLoader cl = LangUtils.findClassLoader(getClass());
		
		// Scans classpath looking for configuration files
		Enumeration<URL> enumResources = null;
		try {
			enumResources = cl.getResources(CONFIG_RESOURCE);
		} catch(IOException ex) {
			throw new RuntimeException(ex);
		}
		
		// Initialize configurations
		while(enumResources.hasMoreElements()) {
			URL url = enumResources.nextElement();
			try {
				for(DirectoryConfig config : parseConfig(url)) {
					try {
						Class clazz = loadClass(config.className, AbstractDirectory.class);
						if(clazz != null) {
							final AbstractDirectory dirInstance = (AbstractDirectory)clazz.newInstance();
							directories.put(config.scheme, dirInstance);
							logger.info("Directory registered [{}]", config.className);
						}
					} catch(InstantiationException | IllegalAccessException ex1) {
						logger.error("Directory instantiation failure [{}]", config.className, ex1);
					}
				}
			} catch(ConfigurationException ex) {
				logger.error("Error while reading configuration [{}]", url.toString(), ex);
			}
		}
	}
	
	public AbstractDirectory getDirectory(String scheme) {
		return directories.get(scheme);
	}
	
	private ArrayList<DirectoryConfig> parseConfig(final URL uri) throws ConfigurationException {
		ArrayList<DirectoryConfig> configs = new ArrayList();
		XMLConfiguration config = new XMLConfiguration(uri);
		List<HierarchicalConfiguration> elDirectories = config.configurationsAt("authDirectory");
		for(HierarchicalConfiguration elDirectory : elDirectories) {
			String scheme = elDirectory.getString("[@scheme]");
			if(StringUtils.isBlank(scheme)) throw new ConfigurationException("Missing attribute [scheme]");
			String className = elDirectory.getString("[@class-name]");
			if(StringUtils.isBlank(className)) throw new ConfigurationException("Missing attribute [class-name]");
			
			configs.add(new DirectoryConfig(scheme, className));
		}
		
		return configs;
	}
	
	private Class loadClass(String className, Class absClass) {
		Class clazz = null;
		try {
			clazz = Class.forName(className);
			if(!absClass.isAssignableFrom(clazz)) throw new ClassCastException();
			return clazz;

		} catch(ClassNotFoundException ex) {
			logger.debug("Class not found [{}]", className);
		} catch(ClassCastException ex) {
			logger.warn("Class must extends '{}' class", absClass.toString());
		} catch(Throwable t) {
			logger.error("Unable to load class [{}]", className, t);
		}
		return null;
	}
	
	private static class DirectoryConfig {
		public String scheme;
		public String className;
		
		public DirectoryConfig(String scheme, String className) {
			this.scheme = scheme;
			this.className = className;
		}
	}
}
