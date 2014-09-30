/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.sonicle.security.otp;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 *
 * @author matteo
 */
public class ReseedingSecureRandom {
	
	private static final int MAX_OPERATIONS = 1000000;
	private final String provider;
	private final String algorithm;
	private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
	private final Lock readLock = lock.readLock();
	private final Lock writeLock = lock.writeLock();
	private final AtomicInteger count = new AtomicInteger(0);
	private SecureRandom secureRandom;

	public ReseedingSecureRandom() {
		this.algorithm = null;
		this.provider = null;
		buildSecureRandom();
	}

	public ReseedingSecureRandom(String algorithm) {
		if(algorithm == null) throw new IllegalArgumentException("Algorithm cannot be null.");
		this.algorithm = algorithm;
		this.provider = null;
		buildSecureRandom();
	}

	public ReseedingSecureRandom(String algorithm, String provider) {
		if(algorithm == null) throw new IllegalArgumentException("Algorithm cannot be null.");
		if(provider == null) throw new IllegalArgumentException("Provider cannot be null.");
		this.algorithm = algorithm;
		this.provider = provider;
		buildSecureRandom();
	}

	private void buildSecureRandom() {
		try {
			if (this.algorithm == null && this.provider == null) {
				this.secureRandom = new SecureRandom();
			} else if (this.provider == null) {
				this.secureRandom = SecureRandom.getInstance(this.algorithm);
			} else {
				this.secureRandom = SecureRandom.getInstance(this.algorithm, this.provider);
			}
		} catch(NoSuchAlgorithmException ex) {
			throw new OTPException(MessageFormat.format("Could not initialise SecureRandom with the specified algorithm [{}]", this.algorithm), ex);
		} catch(NoSuchProviderException ex) {
			throw new OTPException(MessageFormat.format("Could not initialise SecureRandom with the specified provider [{}]", this.provider), ex);
		}
	}

	public void nextBytes(byte[] bytes) {
		readLock.lock();
		int currentCount = count.incrementAndGet();
		if (currentCount > MAX_OPERATIONS) {
			readLock.unlock();
			writeLock.lock();

			try {
				currentCount = count.get();
				if (currentCount > MAX_OPERATIONS) {
					buildSecureRandom();
					count.set(0);
				}
				readLock.lock();
			} finally {
				writeLock.unlock();
			}
		}

		try {
			this.secureRandom.nextBytes(bytes);
		} finally {
			readLock.unlock();
		}
	}
}