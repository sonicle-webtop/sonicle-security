/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security.otp.provider;

import com.sonicle.security.otp.OTPException;
import com.sonicle.security.otp.OTPKey;
import com.sonicle.security.otp.OTPProviderBase;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author matteo
 */
public class SonicleAuth extends OTPProviderBase {
	
	public static final long DEFAULT_KEY_VALIDATION_INTERVAL = 60;

	@Override
	public String getName() {
		return "TimeExpire";
	}

	public OTPKey generateCredentials() {
		return generateCredentials("");
	}
	
	public OTPKey generateCredentials(String base) {
		return new OTPKey(String.valueOf(new Date().getTime()), calculateCode(base));
	}
	
	public boolean check(int userCode, int code, long codeTimestamp) {
		return checkCode(userCode, code, codeTimestamp, DEFAULT_KEY_VALIDATION_INTERVAL);
	}
	
	public boolean check(int userCode, int code, long codeTimestamp, long validationInterval) {
		return checkCode(userCode, code, codeTimestamp, validationInterval);
	}
	
	protected static int calculateCode(String base) {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.reset();
			String hash = base + String.valueOf(new Date().getTime());
			byte[] bytes = md.digest(hash.getBytes());
			BigInteger number = new BigInteger(1, bytes);
			String code = number.toString(8);
			return Integer.valueOf(StringUtils.rightPad(StringUtils.right(code, 6), 6, "0"));
			
		} catch (NoSuchAlgorithmException ex) {
			throw new OTPException("The operation cannot be performed now.");
		}	
	}
	
	protected static boolean checkCode(int userCode, int code, long codeTimestamp, long validationInterval) {
		long now = new Date().getTime();
		long msInterval = TimeUnit.SECONDS.toMillis(validationInterval);
		if((now - codeTimestamp) <= msInterval) {
			return String.valueOf(userCode).equals(String.valueOf(code));
		} else {
			return false;
		}
	}
}
