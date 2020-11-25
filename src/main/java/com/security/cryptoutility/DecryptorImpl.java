package com.security.cryptoutility;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

/**
 * Created by jsundi on 6/2/16.
 * Updated by Raghav S on 6/30/16
 */
@Singleton
class DecryptorImpl implements Decryptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptorImpl.class);

    KeyManagementServices keyManagementServices;

    CryptoServices cryptoServices;

    @Inject
    private DecryptorImpl(KeyManagementServices keyManagementServices,
                          CryptoServices cryptoServices) {

        this.keyManagementServices = keyManagementServices;

        this.cryptoServices = cryptoServices;
    }

    public void initialize() throws EDUSException{

        cryptoServices.initialize(CryptoServices.CryptoOperationMode.DECRYPT);
    }

    public void uninitialize() throws EDUSException{

        cryptoServices.uninitialize();
    }

    public byte[] envelopeDecrypt(MessageProtoc.Message message) {
        byte[] decrytedData = null;
        try{
            decrytedData = getDecryptedDataFromMetaData(message);
        }catch (Exception e){

            LOGGER.error(e.toString(), e.getCause());

            decrytedData = null;
        }
        return decrytedData;
    }

    private SecretKey decryptKey(String kekID, String encryptedKey) throws EDUSException{

        byte[] decryptedKeyBytes = null;

        decryptedKeyBytes = keyManagementServices.decrypt(kekID, encryptedKey);

        SecretKey decryptedKey = new SecretKeySpec(decryptedKeyBytes,
                cryptoServices.getCryptoPolicy().getEncryptionAlgorithmString());

        return decryptedKey;
    }

    private byte[] getDecryptedDataFromMetaData(MessageProtoc.Message message)
                            throws DestroyFailedException, EDUSException{
        byte[] decryptedData = null;

        String kekId = message.getMasterkeyid();

        //byte[] kekBytes = keyManagementServices.getKeyBytes(kekId);

        CryptoPolicy cryptoPolicyKeyMgmtSystem = keyManagementServices.getKeyManagementPolicy().getCryptoPolicy();

        //SecretKey kek = new SecretKeySpec(kekBytes, cryptoPolicyKeyMgmtSystem.getEncryptionAlgorithmString());

        //Arrays.fill(kekBytes, (byte)0);

        String encryptedKey = message.getDatakey();

        SecretKey secretKey = decryptKey(kekId, encryptedKey);

        CipherData cipherData = new CipherData();

        cipherData.setCipherData(message.getCipherdata().getEncrypted().toByteArray());

        cipherData.setIv(message.getCipherdata().getIv().toByteArray());

        cipherData.setSecretKey(secretKey);

        decryptedData = cryptoServices.decryptWithKey(cipherData);
        //kek.destroy();

        return decryptedData;
    }


}
