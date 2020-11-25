package com.security.cryptoutility;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.name.Names;
import org.apache.commons.codec.binary.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;

import static org.junit.Assert.*;

/**
 * Created by cloudera on 9/22/16.
 */
public class CryptoServicesTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoServicesTest.class);

    private CryptoServices cryptoServices;

    private CryptoPolicy cryptoPolicy;

    private CryptoPolicy.Algorithm  algorithm = CryptoPolicy.Algorithm.AES_CBC_HMACSHA256;

    private final String API_KEY_ID = "v2-948b8e506b941";

    private final String API_SECRET_KEY = "/home/cloudera/.idps/key_v2-948b8e506b941.pem";

    private final String ENDPOINT = "IDEA-Trinity-Playground-HCGIWCXBZE0E.pd.idps.a.company.com";

    class CryptoServicesTestModule extends AbstractModule {

        private CryptoPolicy.Algorithm algorithm;

        private CryptoPolicy.KeySize encryptionKeySize;

        private CryptoPolicy.KeySize macKeySize;

        private Properties connectionProperties;


        public CryptoServicesTestModule(){


            //this.algorithm = algorithm;

            //this.encryptionKeySize = encryptionKeySize;

            //this.macKeySize = macKeySize;

            connectionProperties = new Properties();

            connectionProperties.put("api_key_id", API_KEY_ID);

            connectionProperties.put("api_secret_key", API_SECRET_KEY);

            connectionProperties.put("endpoint", ENDPOINT);


        }
        protected  void configure() {
            //bind(CryptoPolicy.Algorithm.class).toInstance(this.algorithm);

            //bind(CryptoPolicy.KeySize.class).annotatedWith(Names.named("EncryptionKeySize"))
            //        .toInstance(this.encryptionKeySize);

            //bind(CryptoPolicy.KeySize.class).annotatedWith(Names.named("MACKeySize"))
            //        .toInstance(this.macKeySize);

            bind(Properties.class)
                    .annotatedWith(Names.named("IDPSConnectionProperties"))
                    .toInstance(this.connectionProperties);

            bind(CryptoPolicy.class).to(MockCryptoPolicy.class);

            bind(PRNGenerator.class).to(PRNGeneratorImpl.class);

            bind(CryptoServices.class).to(CryptoServicesImpl.class);

            bind(KeyManagementPolicy.KeyManagementSystem.class)
                    .toInstance(KeyManagementPolicy.KeyManagementSystem.INTUIT);

            bind(KeyManagementPolicy.class).to(DefaultKeyManagementPolicy.class);

            bind(KeyManagementServices.class).to(KeyManagementServicesImpl.class);


        }
    }


    @Before
    public void setup() throws EDUSException {

        Injector injector = Guice.createInjector(this.new CryptoServicesTestModule());
        cryptoServices = injector.getInstance(CryptoServices.class);

        cryptoServices.initialize(CryptoServices.CryptoOperationMode.BOTH);

        cryptoPolicy = injector.getInstance(CryptoPolicy.class);

    }

    @After
    public void destroy() throws EDUSException {

        cryptoServices.uninitialize();
    }

    @Test
    public void testEncryptWithKey() throws EDUSException, GeneralSecurityException{

        assertNotNull(cryptoServices);

        LOGGER.debug("Generate key");

        SecretKey secretKey = generateKey("ENCRYPT", cryptoPolicy.getEncryptionAlgorithmString());
        assertNotNull(secretKey);

        LOGGER.debug("Generate key done");

        byte[] input = generateRandom(1024);

        LOGGER.debug("Encrypt with key");

        CipherData computedOutput = null;
        computedOutput = cryptoServices.encryptWithKey(secretKey, input);
        assertNotNull(computedOutput);

        LOGGER.debug("Encrypt with key done");

        LOGGER.debug("Encryption - test implementation");

        byte[] expectedOutput = null;
        expectedOutput = aesCBCEncryption(secretKey, computedOutput.getIV(), input, true);
        assertNotNull(expectedOutput);

        LOGGER.debug("Encryption - test implementation completed");

        assertArrayEquals(expectedOutput, computedOutput.getCipherData());

        LOGGER.debug("Decrypt with key");

        byte[] decryptedData = null;
        decryptedData = cryptoServices.decryptWithKey(computedOutput);
        assertNotNull(decryptedData);

        LOGGER.debug("Decrypt with key done");

        assertArrayEquals(input, decryptedData);

    }


    @Test
    public void testMacWithKey() throws EDUSException, GeneralSecurityException {

        assertNotNull(cryptoServices);

        SecretKey integrityKey = generateKey("MAC", cryptoPolicy.getMacAlgorithmString());
        assertNotNull(integrityKey);

        byte[] input = generateRandom(1024);

        IntegrityData computedOutput = cryptoServices.computeMac(integrityKey, input);
        byte[] expectedOutput = hmacSHA256Compute(integrityKey, input);

        assertArrayEquals(expectedOutput, computedOutput.getMac());
        assertTrue(cryptoServices.verifyMac(computedOutput, input));


    }

    @Test
    public void testEncryptKey() throws EDUSException, GeneralSecurityException{

        assertNotNull(cryptoServices);

        SecretKey key = generateKey("ENCRYPT", cryptoPolicy.getEncryptionAlgorithmString());

        byte[] keyblob = new byte[256];

        String computedString = cryptoServices.encryptKey(key, keyblob);

        byte[] iv = Base64.decodeBase64(computedString.split(":")[0]);

        byte[] expectedBytes = aesCBCEncryption(key, iv, keyblob, true);

        String expectedString = computedString.split(":")[0] + ":" + Base64.encodeBase64String(expectedBytes);

        assertEquals(expectedString, computedString);

        SecretKey keyDecrypted =  cryptoServices.decryptKey(key, computedString);

        assertArrayEquals(keyblob, keyDecrypted.getEncoded());
    }


    // Handle types ENCRYPT and MAC
    private SecretKey generateKey(String type, String algorithm) throws GeneralSecurityException{

        SecretKey secretKey = null;
        int keySize = 0;
        if( type.equals("ENCRYPT") ) {
            keySize = cryptoPolicy.getEncryptKeySize();
        } else {
            keySize = cryptoPolicy.getMacKeySize();
        }
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] keyBytes = new byte[keySize];
        secureRandom.nextBytes(keyBytes);
        secretKey = new SecretKeySpec(keyBytes, algorithm);

        return secretKey;
    }

    private byte[] generateRandom(int size){
        byte[] randomData = new byte[size];
        Random random = new Random();
        random.nextBytes(randomData);
        return randomData;
    }

    private byte[] aesCBCEncryption(SecretKey secretKey, byte[] iv, byte[] data, boolean padding) throws GeneralSecurityException{
        byte[] output = null;

        Cipher aesCipher = null;
        if(padding) {
            aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } else {
            aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
        }
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        output = aesCipher.doFinal(data);

        return output;
    }

    private byte[] hmacSHA256Compute(SecretKey integrityKey, byte[] data) throws GeneralSecurityException{
        byte[] output = null;

        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        hmacSha256.init(integrityKey);
        output = hmacSha256.doFinal(data);
        return output;
    }

}
