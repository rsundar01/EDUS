package com.security.cryptoutility;

import javax.crypto.SecretKey;

/**
 * Created by cloudera on 9/19/16.
 */
class IntegrityData {

    private byte[] mac;

    private SecretKey integrityKey;

    public void setMac(byte[] mac){
        this.mac = mac;
    }

    public byte[] getMac(){
        return mac;
    }

    public void setIntegrityKey(SecretKey integrityKey){
        this.integrityKey = integrityKey;
    }

    public SecretKey getInterityKey(){
        return integrityKey;
    }
}
