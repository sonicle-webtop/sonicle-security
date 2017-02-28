/* 
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
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program; if not, see http://www.gnu.org/licenses or write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA.
 *
 * You can contact Sonicle S.r.l. at email address sonicle[at]sonicle[dot]com
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
 * @author malbinola
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
			throw new OTPException(MessageFormat.format("Could not initialise SecureRandom with the specified algorithm [{0}]", this.algorithm), ex);
		} catch(NoSuchProviderException ex) {
			throw new OTPException(MessageFormat.format("Could not initialise SecureRandom with the specified provider [{0}]", this.provider), ex);
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
