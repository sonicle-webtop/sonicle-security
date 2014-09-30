/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security.otp.provider;

import com.sonicle.security.otp.OTPKey;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author matteo
 */
public class GoogleAuthOTPKey extends OTPKey {
	
	private static final String QR_URL_FORMAT = "https://www.google.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl={0}";
	public static final String AUTHENTICATOR_URI_FORMAT = "otpauth://totp/{0}:{1}?secret={2}&issuer={3}";
	
	private final List<Integer> scratchCodes;
	
	public GoogleAuthOTPKey(String secretKey, int code, List<Integer> scratchCodes) {
		super(secretKey, code);
		this.scratchCodes = new ArrayList<Integer>(scratchCodes);
	}
	
	public List<Integer> getScratchCodes() {
		return this.scratchCodes;
	}
	
	public static String buildQRBarcodeURL(String issuer, String secret, String account) {
		return MessageFormat.format(QR_URL_FORMAT, buildAuthenticatorURI(issuer, secret, account));
	}
	
	public static String buildAuthenticatorURI(String issuer, String secret, String account) {
		return MessageFormat.format(AUTHENTICATOR_URI_FORMAT, issuer, account, secret, issuer);
	}
}
