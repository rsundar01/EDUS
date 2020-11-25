package com.security.cryptoutility;

import com.google.inject.Inject;

import java.util.List;

/**
 * Created by cloudera on 10/17/16.
 */
class KeyManagementServicesImpl implements KeyManagementServices {

    private KeyManagementPolicy keyManagementPolicy;

    private KeyManagementServices keyManagementServices;

    private boolean isInitialized = false;

    @Inject
    public KeyManagementServicesImpl(KeyManagementPolicy keyManagementPolicy) throws EDUSException{

        this.keyManagementPolicy = keyManagementPolicy;
    }

    public void initialize() throws EDUSException{

        this.keyManagementServices = keyManagementPolicy.getKeyMangementServices();

        this.keyManagementServices.initialize();

        isInitialized = true;
    }


    private void checkAndInitialize() throws EDUSException {

        if(!isInitialized){

            initialize();
        }
    }

    public KeyManagementPolicy getKeyManagementPolicy(){

        return this.keyManagementPolicy;
    }

    public boolean generateKey(String keyID) throws EDUSException{

        checkAndInitialize();

        return keyManagementServices.generateKey(keyID);
    }

    public boolean updateKey(String keyID) throws EDUSException{

        checkAndInitialize();

        return keyManagementServices.updateKey(keyID);
    }

    public byte[] getKeyBytes(String kekID) throws EDUSException{

        checkAndInitialize();

        return keyManagementServices.getKeyBytes(kekID);
    }

    public byte[] getSeed(int size) throws EDUSException{

        checkAndInitialize();

        return keyManagementServices.getSeed(size);
    }

    public byte[] getRandomBytes(int size) throws EDUSException{

        checkAndInitialize();

        return keyManagementServices.getRandomBytes(size);
    }

    public String encrypt(String kekId, byte[] keyblob) throws EDUSException{

        checkAndInitialize();

        return keyManagementServices.encrypt(kekId, keyblob);
    }

    public String encryptWithVersion(String keyId, byte[] blob, int version) throws EDUSException{

        checkAndInitialize();

        return keyManagementServices.encryptWithVersion(keyId, blob, version);
    }

    public byte[] decrypt(String kekId, String encryptedKeyString) throws EDUSException{

        checkAndInitialize();

        return keyManagementServices.decrypt(kekId, encryptedKeyString);
    }

    public byte[] decryptWithVersion(String keyId, String encryptedString, int version) throws EDUSException{

        checkAndInitialize();

        return keyManagementServices.decryptWithVersion(keyId, encryptedString, version);
    }

    /** Key management system  management **/
    // Get the instance key management system type
    public KeyManagementPolicy.KeyManagementSystem getKeyManagementSystem() throws EDUSException{

        checkAndInitialize();

        return keyManagementServices.getKeyManagementSystem();
    }

    /** Methods to manage Key Encryption Key list **/
    // Set Key Encryption Key(kek) list. Throws EDUSException if operation failed
    public void loadKeyList(List<String> kekList) throws EDUSException{

        checkAndInitialize();

        keyManagementServices.loadKeyList(kekList);
    }

    public void generateKeyList(List<String> keyList) throws EDUSException{

        checkAndInitialize();

        keyManagementServices.generateKeyList(keyList);
    }

    // Create new versions of keys in the kek list
    // Throws EDUSException if operation failed
    public void updateKeyList() throws EDUSException{

        checkAndInitialize();

        keyManagementServices.updateKeyList();
    }

    // Spit out a random key id from the list. Returns null if kek list is null.
    public String getRandomKeyIDFromList() throws EDUSException{

        checkAndInitialize();

        return keyManagementServices.getRandomKeyIDFromList();
    }
}
