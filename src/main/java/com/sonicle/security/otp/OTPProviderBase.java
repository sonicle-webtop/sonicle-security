/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security.otp;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author matteo
 */
public abstract class OTPProviderBase implements IOTPProvider {
	
	protected Map<String, Object> properties = new HashMap<String, Object>();
	
	public void setProperties(Map<String, Object> props) {
		this.properties = props;
	}
	
	public Map<String, Object> getProperties() {
		return properties;
	}
}
