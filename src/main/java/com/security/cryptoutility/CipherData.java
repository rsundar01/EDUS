package com.security.cryptoutility;

import javax.crypto.SecretKey;

/**
 * Created by Raghav S on 6/30/16.
 */
class CipherData {

    private byte[] iv;

    private byte[] cipherData;

    private SecretKey secretKey;

    public void setIv(byte[] iv){
        this.iv = iv;
    }

    public byte[] getIV(){
        return this.iv;
    }

    public void setCipherData(byte[] cipherData){
        this.cipherData = cipherData;
    }

    public byte[] getCipherData(){
        return cipherData;
    }

    public void setSecretKey(SecretKey secretKey){
        this.secretKey = secretKey;
    }

    public SecretKey getSecretKey(){
        return secretKey;
    }

}
