/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security.otp;

/**
 *
 * @author matteo
 */
public class OTPKey {
	
	private final String key;
	private final int verificationCode;
	
	public OTPKey(String secretKey, int code) {
		this.key = secretKey;
		this.verificationCode = code;
	}
	
	public String getKey() {
		return this.key;
	}
	
	public int getVerificationCode() {
		return this.verificationCode;
	}
}