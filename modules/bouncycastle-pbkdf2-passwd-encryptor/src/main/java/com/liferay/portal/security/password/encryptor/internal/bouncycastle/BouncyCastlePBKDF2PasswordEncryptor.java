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
 * class BouncyCastlePBKDF2PasswordEncryptor: Implementation of the PBKDF2 password encryption but
 * using the BouncyCastle implementation for the actual hashing.
 *
 * @author dnebinger
 */
@Component(
		immediate = true,
	property = "type=BCPBKDF2WithHmacSHA1",
	service = PasswordEncryptor.class
)
public class BouncyCastlePBKDF2PasswordEncryptor extends BaseBouncyCastlePBKDF2PasswordEncryptor implements PasswordEncryptor {

}