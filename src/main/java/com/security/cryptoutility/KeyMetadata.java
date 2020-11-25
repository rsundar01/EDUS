package com.security.cryptoutility;

/**
 * Created by cloudera on 10/12/16.
 */
class KeyMetadata {

    private int version;

    public KeyMetadata(int version){
        this.version = version;
    }

    public void setKeyVersion(int version){
        this.version = version;
    }

    public int getKeyVersion(){
        return version;
    }
}
