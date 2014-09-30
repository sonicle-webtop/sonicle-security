/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security.otp;

import java.util.Map;

/**
 *
 * @author matteo
 */
public interface IOTPProvider {
	
	public String getName();
	public void setProperties(Map<String, Object> props);
	public Map<String, Object> getProperties();
}
