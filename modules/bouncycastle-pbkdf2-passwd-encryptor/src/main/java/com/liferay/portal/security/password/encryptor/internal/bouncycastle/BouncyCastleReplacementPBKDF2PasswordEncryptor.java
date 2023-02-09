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

import com.liferay.portal.kernel.security.pwd.PasswordEncryptor;
import org.osgi.service.component.annotations.Component;

/**
 * class BouncyCastleReplacementPBKDF2PasswordEncryptor: This PasswordEncryptor will register to
 * handle Liferay's type, so basically is a replacement PBKDF2 implementation.
 *
 * However, it will likely require blocklisting Liferay's PBKDF2 component for this one to be
 * used, as I just don't have confidence that the service tracker map used by the
 * CompositePasswordEncryptor will correctly use this implementation over Liferay's 100% of the time.
 *
 * @author dnebinger
 */
@Component(
		immediate = true,
	property = {
			"type=" + PasswordEncryptor.TYPE_PBKDF2,
			"service.ranking:Integer=100"
	},
	service = PasswordEncryptor.class
)
public class BouncyCastleReplacementPBKDF2PasswordEncryptor extends BaseBouncyCastlePBKDF2PasswordEncryptor implements PasswordEncryptor {

}