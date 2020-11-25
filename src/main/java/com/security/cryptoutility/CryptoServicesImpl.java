package com.security.cryptoutility;

import com.google.inject.Inject;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;


/**
 * Created by Raghav S on 6/30/16
 * CryptoServices provides basic crypto operations. The implementation contains a Cipher object and
 * a PRN Generator object which are tied to the life time of this object. This implementation is not
 * thread safe. Code using this class is expected to implement thread safety.
 */
class CryptoServicesImpl implements CryptoServices {

    private static final Logger LOGGER = LoggerFactory.getLogger(PRNGeneratorImpl.class);

    private final CryptoPolicy cryptoPolicy;
    private final PRNGenerator prnGenerator;
    private Cipher cipher;
    private Mac mac;
    private CryptoOperationMode cryptoOperationMode;

    @Inject
    public CryptoServicesImpl(CryptoPolicy cryptoPolicy,
                                  PRNGenerator prnGenerator){

        this.cryptoPolicy = cryptoPolicy;

        this.prnGenerator = prnGenerator;

    }

    public void initialize(CryptoOperationMode cryptoOperationMode) throws EDUSException{

        LOGGER.info("Initializing CryptoServices");

        try {

            this.cryptoOperationMode = cryptoOperationMode;

            //Get provider string
            String provider = cryptoPolicy.getJCEProvider();

            //Get cipher control string
            String algorithm = cryptoPolicy.getCipherTranformation();

            this.cipher = Cipher.getInstance(algorithm, provider);

            //Get mac algo string
            String macAlgorithm = cryptoPolicy.getMacAlgorithmString();

            mac = Mac.getInstance(macAlgorithm, provider);

            //PRNGenerator not initialized for decrypt mode
            if(cryptoOperationMode != CryptoOperationMode.DECRYPT) {

                prnGenerator.initialize();

            }

        }catch (Exception e){

            throw new EDUSException(e);
        }

    }

    public void uninitialize() throws EDUSException{

        LOGGER.info("Uninitializing CryptoServices");

        if(cryptoOperationMode != CryptoOperationMode.DECRYPT) {

            prnGenerator.uninitialize();

        }
    }

    public CryptoPolicy getCryptoPolicy(){

        return this.cryptoPolicy;
    }

    public CipherData encryptWithRandomKey(byte[] data) throws EDUSException{

        CipherData cipherData = null;

        try {

            SecretKey secretKey = generateKey(cryptoPolicy.getEncryptionAlgorithmString());

            cipherData = encryptWithKey(secretKey, data);

        } catch (Exception e){

            throw new EDUSException(e);

        }

        return cipherData;
    }

    public CipherData encryptWithKey(SecretKey secretKey, byte[] data) throws EDUSException{

        CipherData cipherData = null;

        try {

            cipherData = encrypt(secretKey, data);

            cipherData.setSecretKey(secretKey);

        } catch (Exception e){

            throw new EDUSException(e);
        }

        return cipherData;
    }

    public byte[] decryptWithKey(CipherData cipherData) throws EDUSException {

        try {

            return decrypt(cipherData);

        }catch (Exception e){
            throw new EDUSException(e);
        }

    }

    public String encryptKey(SecretKey kek, byte[] keyblob) throws EDUSException{

        try {
            //Encrypt the keyblob
            CipherData cipherData = encrypt(kek, keyblob);

            byte[] encryptedData = cipherData.getCipherData();
            byte iv[] = cipherData.getIV();

            String encryptedKey = Base64.encodeBase64String(iv) + ":" + Base64.encodeBase64String(encryptedData);

            return encryptedKey;
        }catch (Exception e){
            throw new EDUSException(e);
        }
    }

    public SecretKey decryptKey(SecretKey secretKey, String encryptedKeyString) throws EDUSException{

        try {

            // Read and split encrypted key string
            String ivBase64 = encryptedKeyString.split(":")[0];
            String encryptedKeyBase64 = encryptedKeyString.split(":")[1];

            // Build Cipher Data
            CipherData cipherData = new CipherData();
            cipherData.setCipherData(Base64.decodeBase64(encryptedKeyBase64));
            cipherData.setIv(Base64.decodeBase64(ivBase64));
            cipherData.setSecretKey(secretKey);

            byte[] decryptedKeyBytes = decrypt(cipherData);

            SecretKey decryptedKey = new SecretKeySpec(decryptedKeyBytes, cryptoPolicy.getEncryptionAlgorithmString());

            return decryptedKey;
        }catch(Exception e){
            throw new EDUSException(e);
        }
    }

    public IntegrityData computeMacWithRandomKey(byte[] macData) throws EDUSException{
        try {

            SecretKey integrityKey = generateKey(cryptoPolicy.getMacAlgorithmString());

            IntegrityData integrityData = computeMac(integrityKey, macData);

            return integrityData;
        }catch(Exception e){
            throw new EDUSException(e);
        }
    }

    public IntegrityData computeMac(SecretKey integrityKey, byte[] macData) throws EDUSException{

        try {
            IntegrityData integrityData = mac(integrityKey, macData);

            integrityData.setIntegrityKey(integrityKey);

            return integrityData;
        }catch(Exception e){
            throw new EDUSException(e);
        }
    }

    public boolean verifyMac(IntegrityData integrityData, byte[] dataToMac) throws EDUSException {

        try {
            IntegrityData computedIntegrityData = mac(integrityData.getInterityKey(), dataToMac);

            return Arrays.equals(integrityData.getMac(), computedIntegrityData.getMac());
        }catch(Exception e){
            throw new EDUSException(e);
        }

    }


    private SecretKey generateKey(String algorithm) throws EDUSException{

        //***** Verify KeyGenerator implementation to find out the details and compare against this implementation
        //KeyGenerator keyGenerator = KeyGenerator.getInstance("AES"); keyGenerator.init(128);
        int keySize = cryptoPolicy.getEncryptKeySize();

        byte[] randomData = new byte[keySize];
        randomData = prnGenerator.getRandomBytes(randomData.length);

        SecretKey key = new SecretKeySpec(randomData, algorithm);

        Arrays.fill(randomData, (byte)0);

        return key;

    }

    private CipherData encrypt(SecretKey secretKey, byte[] inputClearData) throws GeneralSecurityException, EDUSException {

        //Get IV
        int blockSize = cryptoPolicy.getBlockSize();
        byte[] randomBytes = new byte[blockSize];
        randomBytes = prnGenerator.getRandomBytes(randomBytes.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(randomBytes);

        //Get Cipher instance
        //*** Test/Verify AES Implementation to ensure if no other random bytes are required for processing *****/
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        //Perform encryption
        byte[] encryptedData = cipher.doFinal(inputClearData);
        byte[] iv = cipher.getIV();

        CipherData cipherData = new CipherData();
        cipherData.setCipherData(encryptedData);
        cipherData.setIv(iv);

        return cipherData;
    }


    private byte[] decrypt(CipherData cipherData) throws GeneralSecurityException {
        //Get IV
        IvParameterSpec ivParameterSpec = new IvParameterSpec(cipherData.getIV());

        cipher.init(Cipher.DECRYPT_MODE, cipherData.getSecretKey(), ivParameterSpec);

        //Perform decryption
        byte[] clearData = cipher.doFinal(cipherData.getCipherData());

        return clearData;
    }

    private IntegrityData mac(SecretKey macKey, byte[] data) throws GeneralSecurityException{

        mac.init(macKey);

        //Perform mac
        byte[] computedMac = mac.doFinal(data);

        IntegrityData integrityData = new IntegrityData();
        integrityData.setMac(computedMac);

        return integrityData;
    }



}
