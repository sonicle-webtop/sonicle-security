/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security.otp;

import java.lang.reflect.Constructor;
import java.text.MessageFormat;
import java.util.HashMap;

/**
 *
 * @author matteo
 */
public class OTPProviderFactory {
	
	private static final HashMap<String, OTPProviderBase> providers = new HashMap<String, OTPProviderBase>();
	
	public static synchronized OTPProviderBase getInstance(String providerName) {
		String className = null;
		
		try {
			// Defines fully qualified class name
			if(providerName.equals("TOTP") || providerName.equals("SonicleAuth") || providerName.equals("GoogleAuth")) {
				className = MessageFormat.format("com.sonicle.security.otp.provider.{0}", providerName);
			} else {
				className = providerName;
			}
			
			// Lookup class instance
			if(!providers.containsKey(className)) {
				Class clazz = Class.forName(className);
				Constructor<OTPProviderBase> constructor = clazz.getConstructor();
				providers.put(className, constructor.newInstance());
			}
			return providers.get(className);
		} catch (Exception ex) {
			throw new RuntimeException(MessageFormat.format("Unable to instantiate OTP provider class. [{0}]", className), ex);
		}
	}
}