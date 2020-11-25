package com.security.cryptoutility;

/**
 * Created by cloudera on 11/10/16.
 */
class KMSRandomSource implements RandomSource {

    private KeyManagementServices keyManagementServices;

    public KMSRandomSource(KeyManagementServices keyManagementServices){

        this.keyManagementServices = keyManagementServices;
    }

    public byte[] getSeed(int size) throws EDUSException{

        return keyManagementServices.getRandomBytes(size);
    }

    public String getRandomSource() throws EDUSException{

        return keyManagementServices.getKeyManagementSystem().name();
    }

}
