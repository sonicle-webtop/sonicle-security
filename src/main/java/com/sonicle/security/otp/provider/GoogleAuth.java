/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security.otp.provider;

import com.sonicle.security.otp.OTPException;
import com.sonicle.security.otp.OTPKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 *
 * @author matteo
 */
public class GoogleAuth extends TOTP {
	
	private static final int DEFAULT_SCRATCH_CODES = 5;
	private static final int DEFAULT_SCRATCH_CODE_LENGTH = 8;
	private static final int DEFAULT_BYTES_PER_SCRATCH_CODE = 4;
	public static final int DEFAULT_SCRATCH_CODE_MODULUS = (int) Math.pow(10, DEFAULT_SCRATCH_CODE_LENGTH);
	private static final int SCRATCH_CODE_INVALID = -1;
	
	public GoogleAuth() {
		
	}
	
	@Override
	public String getName() {
		return "GoogleAuth";
	}
	
	@Override
	public OTPKey generateCredentials() {
		byte[] buffer = new byte[getSecretBits()/8 + DEFAULT_SCRATCH_CODES * DEFAULT_BYTES_PER_SCRATCH_CODE];
		this.secureRandom.nextBytes(buffer);
		
		// Extracting the bytes making up the secret key
		byte[] secretKey = Arrays.copyOf(buffer, getSecretBits()/8);
		String generatedKey = calculateSecretKey(secretKey);
		
		int validationCode = calculateValidationCode(secretKey);
		List<Integer> scratchCodes = calculateScratchCodes(buffer);
		
		return new GoogleAuthOTPKey(generatedKey, validationCode, scratchCodes);
	}
	
	private List<Integer> calculateScratchCodes(byte[] buffer) {
		List<Integer> scratchCodes = new ArrayList<Integer>();
		
		while (scratchCodes.size() < DEFAULT_SCRATCH_CODES) {
			byte[] scratchCodeBuffer = Arrays.copyOfRange(
				buffer,
				getSecretBits()/8 + DEFAULT_BYTES_PER_SCRATCH_CODE * scratchCodes.size(),
				getSecretBits()/8 + DEFAULT_BYTES_PER_SCRATCH_CODE * scratchCodes.size() + DEFAULT_BYTES_PER_SCRATCH_CODE);
			
			int scratchCode = calculateScratchCode(scratchCodeBuffer);
			if(scratchCode != SCRATCH_CODE_INVALID) {
				scratchCodes.add(scratchCode);
			} else {
				scratchCodes.add(generateScratchCode());
			}
		}
		return scratchCodes;
	}
	
	private int calculateScratchCode(byte[] scratchCodeBuffer) {
		if(scratchCodeBuffer.length < DEFAULT_BYTES_PER_SCRATCH_CODE) throw new IllegalArgumentException("The provided random byte buffer is too small.");
	
		int scratchCode = 0;
		for (int i = 0; i < DEFAULT_BYTES_PER_SCRATCH_CODE; ++i) {
			scratchCode <<= 8;
			scratchCode += scratchCodeBuffer[i];
		}
		scratchCode = (scratchCode & 0x7FFFFFFF) % DEFAULT_SCRATCH_CODE_MODULUS;
		
		// Accept the scratch code only if it has exactly SCRATCH_CODE_LENGTH digits.
		if(validateScratchCode(scratchCode)) {
			return scratchCode;
		} else {
			return SCRATCH_CODE_INVALID;
		}
	}
	
	private boolean validateScratchCode(int scratchCode) {
		return (scratchCode >= DEFAULT_SCRATCH_CODE_MODULUS / 10);
	}
	
	private int generateScratchCode() {
		while (true) {
			byte[] scratchCodeBuffer = new byte[DEFAULT_BYTES_PER_SCRATCH_CODE];
			secureRandom.nextBytes(scratchCodeBuffer);
			int scratchCode = calculateScratchCode(scratchCodeBuffer);
			if (scratchCode != SCRATCH_CODE_INVALID) return scratchCode;
		}
	}
}
