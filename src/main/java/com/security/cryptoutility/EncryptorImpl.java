package com.security.cryptoutility;

import com.google.inject.Inject;
import com.google.inject.Singleton;

import java.util.List;
import javax.crypto.*;

import com.google.protobuf.ByteString;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by jsundi on 6/2/16.
 * Updated by Raghav S on 6/30/16
 */
@Singleton
class EncryptorImpl implements Encryptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(Encryptor.class);

    private CryptoServices cryptoServices;

    private KeyManagementServices keyManagementServices;


    @Inject
    private EncryptorImpl(KeyManagementServices keyManagementServices,
                          CryptoServices cryptoServices) {

        this.keyManagementServices = keyManagementServices;

        this.cryptoServices = cryptoServices;
    }

    public void initialize() throws EDUSException{

        LOGGER.debug("Start encryptor initialization");

        cryptoServices.initialize(CryptoServices.CryptoOperationMode.ENCRYPT);

        LOGGER.debug("End encryptor initialization");
    }

    public void uninitialize() throws EDUSException{

        LOGGER.debug("Start encryptor uninitialization");

        cryptoServices.uninitialize();

        LOGGER.debug("End encryptor uninitialization");
    }


    public MessageProtoc.Message envelopeEncryptWithKek(String kekID, byte[] dataBytes) throws EDUSException {

        MessageProtoc.Message message = null;

        message = getEncryptedContentWithMetadata(kekID, dataBytes);

        return message;
    }

    public MessageProtoc.Message envelopeEncryptWithRandomKek(byte[] dataBytes) throws EDUSException {

        MessageProtoc.Message message = null;

        LOGGER.debug("Fetch random key name from key list");

        String kekID = keyManagementServices.getRandomKeyIDFromList();

        LOGGER.debug("Key chosen: " + kekID);

        message = envelopeEncryptWithKek(kekID, dataBytes);

        return message;
    }


    private String encryptKey(String kekID, byte[] dataKeyBytes) throws EDUSException{

        return keyManagementServices.encrypt(kekID, dataKeyBytes);

    }


    private MessageProtoc.Message getEncryptedContentWithMetadata(String kekID, byte[] data)
                                            throws EDUSException {

        MessageProtoc.Message message = null;

        //CryptoPolicy cryptoPolicyKeyMgmtSystem = keyManagementServices.getKeyManagementPolicy().getCryptoPolicy();

        LOGGER.debug("Call encrypt with random key function");

        CipherData cipherData = cryptoServices.encryptWithRandomKey(data);

        LOGGER.debug("Received cipher data");

        // Build cipherData sub-block
        MessageProtoc.Message.CipherData.Builder cipherDataBuilder = MessageProtoc.Message.CipherData.newBuilder();

        cipherDataBuilder.setEncrypted(ByteString.copyFrom(cipherData.getCipherData()));

        cipherDataBuilder.setIv(ByteString.copyFrom(cipherData.getIV()));

        MessageProtoc.Message.CipherData cipherDataMsg = cipherDataBuilder.build();

        // Build message block
        MessageProtoc.Message.Builder messageBuilder = MessageProtoc.Message.newBuilder();

        messageBuilder.setCipherdata(cipherDataMsg);

        SecretKey secretKey = cipherData.getSecretKey();

        String encryptedDataKey = encryptKey(kekID, secretKey.getEncoded());

        messageBuilder.setDatakey(encryptedDataKey);

        messageBuilder.setMasterkeyid(kekID);

        message = messageBuilder.build();

        //kek.destroy();
        //secretKey.destroy();

        LOGGER.debug("crypto message built");

        return message;
    }

    public void initializeKEKPool(List<String> kekPool, boolean generateKeys) throws EDUSException{

        if(generateKeys){

            keyManagementServices.generateKeyList(kekPool);

        } else {

            keyManagementServices.loadKeyList(kekPool);

        }

    }

    public void generateKEK(String kekID) throws EDUSException{

        keyManagementServices.generateKey(kekID);

    }


}
