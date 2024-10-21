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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.hash.provider.bcrypt.constant.Constants;
import org.wso2.carbon.user.core.exceptions.HashProviderClientException;
import org.wso2.carbon.user.core.exceptions.HashProviderException;
import org.wso2.carbon.user.core.hash.HashProvider;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCrypt.Version;

/**
 * This class contains the implementation of BCRYPT hashing algorithm.
 */
public class BCRYPTHashProvider implements HashProvider {

    private static final Log LOG = LogFactory.getLog(BCRYPTHashProvider.class);

    private int cost;

    
    @Override
    public void init() {

    	
//        pseudoRandomFunction = Constants.DEFAULT_BCRYPT_PRF;
//        dkLength = Constants.DEFAULT_DERIVED_KEY_LENGTH;
        cost = Constants.DEFAULT_COST;
//        try {
//            skf = SecretKeyFactory.getInstance(pseudoRandomFunction);
//        } catch (NoSuchAlgorithmException e) {
//            log.error(String.format(ErrorMessage.ERROR_CODE_NO_SUCH_ALGORITHM.getDescription(), pseudoRandomFunction),
//                    e);
//        }
//        
//        //BCrypt 
//        
//        
        
    }

    @Override
    public void init(Map<String, Object> initProperties) throws HashProviderException {

        init();
        Object costObject = initProperties.get(Constants.COST_PROPERTY);
        
        if (costObject != null) {
            if (costObject instanceof String) {
                try {
                    cost = Integer.parseInt(costObject.toString());
                } catch (NumberFormatException e) {
                    throw new HashProviderClientException(
                            ErrorMessage.ERROR_CODE_INVALID_COST.getDescription(),
                            Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                                    ErrorMessage.ERROR_CODE_INVALID_COST.getCode());
                }
                validateCost(cost);
            }
        }

    }

    @Override
    public byte[] calculateHash(char[] plainText, String salt) throws HashProviderException {

    	LOG.info("BCRYPTHashProvider.calculateHash() salt length " +salt  );
    	
        validateEmptyValue(plainText);
        validateEmptySalt(salt);
        return generateHash(plainText, salt, cost);
    }

    @Override
    public Map<String, Object> getParameters() {

        Map<String, Object> bcryptHashProviderParams = new HashMap<>();
        bcryptHashProviderParams.put(Constants.COST_PROPERTY, cost);
        return bcryptHashProviderParams;
    }

    @Override
    public String getAlgorithm() {

        return Constants.BCRYPT_HASHING_ALGORITHM;
    }

    /**
     * Generate hash value according to the given parameters.
     *
     * @param plainText            The plain text value to be hashed.
     * @param salt                 The salt.
     * @param iterationCount       Number of iterations to be used by the PRF.
     * @param dkLength             The output length of the hash function.
     * @return The resulting hash value of the value.
     * @throws HashProviderException If an error occurred while generating the hash.
     */
    private byte[] generateHash(char[] plainText, String salt, int cost)
            throws HashProviderException {
    	
    	LOG.info("BCRYPTHashProvider.generateHash()  "+salt);
    	//TODO SME Version As PARAM 
        Version version = BCrypt.Version.VERSION_2A;
        
       // HashData hashData  = version.parser.parse(hash);
        
        byte[] saltBytesOk = Base64.getDecoder().decode(salt.getBytes(StandardCharsets.UTF_8));
    	
        byte[] hashNewNew   = BCrypt.with(version).hash(cost, saltBytesOk, new String(plainText).getBytes(StandardCharsets.UTF_8) );
    	
        return hashNewNew;
        
    	//return BCrypt.generate(new String(plainText).getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(salt), cost);
   }

    /**
     * This method is responsible fpr validating the value to be hashed.
     *
     * @param plainText The value which needs to be hashed.
     * @throws HashProviderClientException If the hash value is not provided.
     */
    private void validateEmptyValue(char[] plainText) throws HashProviderClientException {

        if (plainText.length == 0) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_EMPTY_VALUE.getDescription(),
                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_EMPTY_VALUE.getCode());
        }
    }

    /**
     * This method is responsible for validating the salt.
     *
     * @param salt The salt which needs to be validated.
     * @throws HashProviderClientException If the salt value is blank.
     */
    private void validateEmptySalt(String salt) throws HashProviderClientException {
        if (StringUtils.isBlank(salt)) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_EMPTY_SALT_VALUE.getDescription(),
                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_EMPTY_SALT_VALUE.getCode());
        }
    }

    /**
     * This method is responsible for validating the iteration count.
     *
     * @param cost The iteration count needs to be validated.
     * @throws HashProviderClientException If the iteration count is negative or equal to zero.
     */
    private void validateCost(int cost) throws HashProviderClientException {
        if (cost < 4 || cost > 31) {
            throw new HashProviderClientException(
                    ErrorMessage.ERROR_CODE_INVALID_COST.getDescription(),
                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
                            ErrorMessage.ERROR_CODE_INVALID_COST.getCode());
        }
    }

//    /**
//     * This method is responsible for validating the derived key length.
//     *
//     * @param dkLength The derived key length needs to be validated.
//     * @throws HashProviderClientException If the derived key length is negative or equal to zero.
//     */
//    private void validateDerivedKeyLength(int dkLength) throws HashProviderClientException {
//
//        if (dkLength <= 0) {
//            throw new HashProviderClientException(
//                    ErrorMessage.ERROR_CODE_INVALID_DERIVED_KEY_LENGTH.getDescription(),
//                    Constants.BCRYPT_HASH_PROVIDER_ERROR_PREFIX +
//                            ErrorMessage.ERROR_CODE_INVALID_DERIVED_KEY_LENGTH.getCode());
//        }
//    }
//
//    /**
//     * This method is responsible for converting the base64 string value value of salt to byte array.
//     *
//     * @param salt The salt.
//     * @return The converted byte array from base64 salt value.
//     */
//    private byte[] base64ToByteArray(String salt) {
//
//        byte[] name = Base64.getEncoder().encode(salt.getBytes(StandardCharsets.UTF_8));
//        return (Base64.getDecoder().decode(name));
//    }
}
