/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.hash.provider.bcrypt;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.exceptions.HashProviderServerException;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCrypt.HashData;
import at.favre.lib.crypto.bcrypt.BCrypt.Result;
import at.favre.lib.crypto.bcrypt.BCrypt.Version;
import at.favre.lib.crypto.bcrypt.IllegalBCryptFormatException;

/**
 * Test class for BCRYPTHashProvider.
 */
public class BCRYPTHashProviderTest {

	private static final Log LOG = LogFactory.getLog(BCRYPTHashProviderTest.class);

	private static BCRYPTHashProvider bcryptHashProvider = null;
	private static Map<String, Object> initProperties;
	private byte[] salt;
	private String saltAsString;

	@BeforeClass
	public void initialize() {

		// salt = Bytes.random(16, new SecureRandom()).array();

		// saltAsString = Base64.getEncoder().encodeToString(salt);

	//	saltAsString = "TT0v/MLzhrYVvYYSrfXQvQ==";

		saltAsString = "BR2z4N3Fe3/8P4zmK6juMQ==";
		
		// Base64.getEncoder().encode(salt).toString();

		// LOG.info("BCRYPTHashProviderTest.initialize() salt length " +salt + " "+
		// salt.length);

		bcryptHashProvider = new BCRYPTHashProvider();
	}

	@DataProvider(name = "initConfig")
	public Object[][] initConfig() {

		bcryptHashProvider.init();
		initProperties = bcryptHashProvider.getParameters();
		int cost = (int) initProperties.get(Constants.COST_PROPERTY);

		return new Object[][] { { cost, Constants.DEFAULT_COST } };
	}

	@Test(dataProvider = "initConfig")
	public void testInitConfig(Object parameters, Object expectedValue) {

		Assert.assertEquals(parameters, expectedValue);
	}

	@DataProvider(name = "initConfigParams")
	public Object[][] initConfigParams() {

		return new Object[][] { { "10" }, { "20" }, { null }, { "4" }, { "31" } };
	}

	@Test(dataProvider = "initConfigParams")
	public void testInitConfigParams(String cost) throws HashProviderException {

		Map<String, Object> initProperties = new HashMap<>();

		if (cost != null) {
			initProperties.put(Constants.COST_PROPERTY, cost);
		}
		bcryptHashProvider.init(initProperties);
		Map<String, Object> bcryptParams = bcryptHashProvider.getParameters();
		if (cost == null) {
			Assert.assertEquals(bcryptParams.get(Constants.COST_PROPERTY), Constants.DEFAULT_COST);
		} else {
			Assert.assertEquals(bcryptParams.get(Constants.COST_PROPERTY), Integer.parseInt(cost));
		}
	}

	@DataProvider(name = "getHash")
	public Object[][] getHash() throws UnsupportedEncodingException {

		return new Object[][] {
				{ "wso2123".toCharArray(), saltAsString, "10",
						"$2a$10$Sfo01AlA2D2h2F25rkb6U.QIFrFCNVfPqcGR3gVAjsiJChjm9qreK".getBytes() },
				{ "john123".toCharArray(), saltAsString, "10",
						"$2a$10$0Fu0pzWPpSe39i1MhyfLu.EGON66FhUe8OsRJmcvOuWKTKOUMyoeG".getBytes() } };
	}

	@Test(dataProvider = "getHash")
	public void testGetHash(char[] plainText, String salt, String cost, byte[] hash)
			throws HashProviderException, IllegalBCryptFormatException {
		LOG.info("BCRYPTHashProviderTest.testGetHash()  " + new String(hash));
		LOG.info("BCRYPTHashProviderTest.testGetHash()  " + new String(hash, StandardCharsets.UTF_8));
		initializeHashProvider(cost);

		// byte[] hash = Base64.getDecoder().decode(hash64);

		Version version = BCrypt.Version.VERSION_2A;

		HashData hashData = version.parser.parse(hash);

		LOG.info("BCRYPTHashProviderTest.testGetHash() hashdata " + hashData);

		String saltStringOk = Base64.getEncoder().encodeToString(hashData.rawSalt);

		LOG.info("BCRYPTHashProviderTest.testGetHash() saltStringOk " + saltStringOk);

		
		byte[] saltBytesOk = Base64.getDecoder().decode(saltStringOk.getBytes());

		byte[] hashNewNew = BCrypt.with(Version.VERSION_2A).hash(10, saltBytesOk, new String(plainText).getBytes());

		LOG.info("BCRYPTHashProviderTest.testGetHash()  " + new String(hashNewNew));
		LOG.info("BCRYPTHashProviderTest.testGetHash()  " + new String(hashNewNew, StandardCharsets.UTF_8));

		byte[] hashNew = bcryptHashProvider.calculateHash(plainText,
				Base64.getEncoder().encodeToString(hashData.rawSalt));

		Assert.assertEquals(hash, hashNewNew);

		LOG.info("BCRYPTHashProviderTest.testGetHash()  " + new String(hashNew));
		LOG.info("BCRYPTHashProviderTest.testGetHash()  " + new String(hashNew, StandardCharsets.UTF_8));

		Assert.assertEquals(hashNew, hash);

		Result result = BCrypt.verifyer().verify(String.valueOf(plainText).getBytes(), hash);

		LOG.info("BCRYPTHashProviderTest.testGetHash() " + result);

		Assert.assertTrue(result.verified);
	}

	@DataProvider(name = "hashProviderErrorScenarios")
	public Object[][] hashProviderErrorScenarios() {

		return new Object[][] { 
			    { "".toCharArray(),         saltAsString, "10", ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode() },
				{ "wso2123".toCharArray() , "", "10", ErrorMessage.ERROR_CODE_EMPTY_SALT_VALUE.getCode() },
				{ "    ".toCharArray(),     saltAsString, "10", ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode() },
				{ "john12".toCharArray(),   "    ", "10", ErrorMessage.ERROR_CODE_EMPTY_SALT_VALUE.getCode() }

		};
	}

	
	@Test(dataProvider = "hashProviderErrorScenarios")
	public void testHashProviderErrorScenarios(char[] plainText, String salt, String cost, String errorCodeExpected)
			throws HashProviderException {

		
		 String errorCodeExpectedWithPrefix = Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX + errorCodeExpected;
		try {
			
			initializeHashProvider(cost);
			bcryptHashProvider.calculateHash(plainText, salt);
		} catch (HashProviderClientException e) {
			Assert.assertEquals(e.getErrorCode(), errorCodeExpectedWithPrefix);
		} catch (HashProviderServerException e) {
			Assert.assertEquals(e.getErrorCode(), errorCodeExpectedWithPrefix);
		}
	}

	@Test
	public void testGetAlgorithm() {

		Assert.assertEquals(bcryptHashProvider.getAlgorithm(), Constants.BCRYPT_HASHING_ALGORITHM);
	}


	/**
	 * Initializing the HashProvider with given meta properties.
	 *
	 * @param iterationCount       The iteration count.
	 * @param dkLength             The derived key length.
	 * @param pseudoRandomFunction The pseudo random function.
	 */
	private void initializeHashProvider(String cost) throws HashProviderException {

		initProperties = new HashMap<>();
		initProperties.put(Constants.COST_PROPERTY, cost);
		bcryptHashProvider.init(initProperties);
	}
}
