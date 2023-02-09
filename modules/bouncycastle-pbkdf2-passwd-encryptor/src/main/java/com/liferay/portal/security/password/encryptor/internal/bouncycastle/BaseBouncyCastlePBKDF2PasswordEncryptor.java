/**
 * Copyright (c) 2000-present Liferay, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.liferay.portal.security.password.encryptor.internal.bouncycastle;

import com.liferay.portal.kernel.exception.PwdEncryptorException;
import com.liferay.portal.kernel.io.BigEndianCodec;
import com.liferay.portal.kernel.security.SecureRandomUtil;
import com.liferay.portal.kernel.security.pwd.PasswordEncryptor;
import com.liferay.portal.kernel.util.*;
import com.liferay.portal.util.PropsUtil;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.osgi.service.component.annotations.Component;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * class BaseBouncyCastlePBKDF2PasswordEncryptor: Implementation of the PBKDF2 password encryption but
 * using the BouncyCastle implementation for the actual hashing.
 *
 * This is just called a base class so we can instantiate two different components each with their
 * own type assignments.
 *
 * @author dnebinger
 */
public abstract class BaseBouncyCastlePBKDF2PasswordEncryptor implements PasswordEncryptor {

	@Override
	public String encrypt(String plainTextPassword, String encryptedPassword)
			throws PwdEncryptorException {

		return encrypt(
				getDefaultPasswordEncryptionAlgorithm(), plainTextPassword,
				encryptedPassword);
	}

	@Override
	public String encrypt(
			String algorithm, String plainTextPassword,
			String encryptedPassword)
			throws PwdEncryptorException {

		return encrypt(algorithm, plainTextPassword, encryptedPassword, false);
	}

	/**
	 * encrypt: This method is basically a lift from Liferay's PBKDF2PasswordEncryptor as it works practially identically
	 * to theirs, the only difference is that when the hash is calculated, it uses BouncyCastle's implementation instead
	 * of the JCE default implementation.
	 *
	 * @param algorithm Algorithm to use, which we now ignore.
	 * @param plainTextPassword The plaintext password to be hashed.
	 * @param encryptedPassword The current encrypted password, actually contains the key size, rounds and salt used for the initial hash calculation.
	 * @param upgradeHashSecurity Flag indicating whether to ignore these things from the encrypted password or not.
	 * @return String The encrypted password string.
	 * @throws PwdEncryptorException in case of exception.
	 */
	@Override
	public String encrypt(
			String algorithm, String plainTextPassword,
			String encryptedPassword, boolean upgradeHashSecurity)
		throws PwdEncryptorException {

		try {
			if (upgradeHashSecurity) {
				encryptedPassword = null;
			}

			BCPBKDF2EncryptionConfiguration bcpbkdf2EncryptionConfiguration =
				new BCPBKDF2EncryptionConfiguration();

			bcpbkdf2EncryptionConfiguration.configure(
				algorithm, encryptedPassword);

			byte[] saltBytes = bcpbkdf2EncryptionConfiguration.getSaltBytes();

			// Okay, so this is the guts of the BC implementation...

			// First we need to get an instance of the PKCS5S2 parameters generator.
			PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();

			// initialize the generator with the password, the salt and the number of rounds to complete
			generator.init(plainTextPassword.getBytes(), saltBytes, bcpbkdf2EncryptionConfiguration.getRounds());

			// Let the generator calculate the hash key and extract the secret key bytes from the key.
			byte[] secretKeyBytes = ((KeyParameter) generator.generateDerivedMacParameters(bcpbkdf2EncryptionConfiguration.getKeySize())).getKey();

			// The rest comes from Liferay's implementation to handle the key size, rounds and salt packing at the front of the key, etc.

			ByteBuffer byteBuffer = ByteBuffer.allocate(
				(2 * 4) + saltBytes.length + secretKeyBytes.length);

			byteBuffer.putInt(bcpbkdf2EncryptionConfiguration.getKeySize());
			byteBuffer.putInt(bcpbkdf2EncryptionConfiguration.getRounds());
			byteBuffer.put(saltBytes);
			byteBuffer.put(secretKeyBytes);

			return Base64.encode(byteBuffer.array());
		}
		catch (Exception exception) {
			throw new PwdEncryptorException(exception.getMessage(), exception);
		}
	}

	@Override
	public String getDefaultPasswordEncryptionAlgorithm() {
		return _PASSWORDS_ENCRYPTION_ALGORITHM;
	}

	private static final int _KEY_SIZE = 160;

	private static final int _ROUNDS = 720000;

	private static final int _SALT_BYTES_LENGTH = 8;

	private static final Pattern _pattern = Pattern.compile(
		"^.*/?([0-9]+)?/([0-9]+)$");

	private static final String _PASSWORDS_ENCRYPTION_ALGORITHM =
			StringUtil.toUpperCase(
					GetterUtil.getString(
							PropsUtil.get(PropsKeys.PASSWORDS_ENCRYPTION_ALGORITHM)));

	private static class BCPBKDF2EncryptionConfiguration {

		public void configure(String algorithm, String encryptedPassword)
			throws PwdEncryptorException {

			if (Validator.isNull(encryptedPassword)) {
				Matcher matcher = _pattern.matcher(algorithm);

				if (matcher.matches()) {
					_keySize = GetterUtil.getInteger(
						matcher.group(1), _KEY_SIZE);

					_rounds = GetterUtil.getInteger(matcher.group(2), _ROUNDS);
				}

				BigEndianCodec.putLong(
					_saltBytes, 0, SecureRandomUtil.nextLong());
			}
			else {
				ByteBuffer byteBuffer = ByteBuffer.wrap(
					Base64.decode(encryptedPassword));

				try {
					_keySize = byteBuffer.getInt();
					_rounds = byteBuffer.getInt();

					byteBuffer.get(_saltBytes);
				}
				catch (BufferUnderflowException bufferUnderflowException) {
					throw new PwdEncryptorException(
						"Unable to extract salt from encrypted password",
						bufferUnderflowException);
				}
			}
		}

		public int getKeySize() {
			return _keySize;
		}

		public int getRounds() {
			return _rounds;
		}

		public byte[] getSaltBytes() {
			return _saltBytes;
		}

		private int _keySize = _KEY_SIZE;
		private int _rounds = _ROUNDS;
		private final byte[] _saltBytes = new byte[_SALT_BYTES_LENGTH];

	}
}