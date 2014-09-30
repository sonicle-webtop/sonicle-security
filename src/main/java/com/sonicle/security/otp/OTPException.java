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
public class OTPException extends RuntimeException {
	
	public OTPException() {
		super();
	}
	
	public OTPException(String message) {
		super(message);
	}
	
	public OTPException(Throwable cause) {
		super(cause);
	}
	
	public OTPException(String message, Throwable cause) {
		super(message, cause);
	}
}
