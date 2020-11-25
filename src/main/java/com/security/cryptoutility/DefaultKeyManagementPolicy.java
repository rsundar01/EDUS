package com.security.cryptoutility;

import com.google.inject.Inject;
import com.google.inject.name.Named;

import java.util.Properties;

/**
 * Created by Raghav S on 10/15/16.
 */
class DefaultKeyManagementPolicy implements KeyManagementPolicy{

    private KeyManagementSystem keyManagementSystem;

    private Properties connectionProperties;

    private CryptoPolicy cryptoPolicy;

    @Inject
    public DefaultKeyManagementPolicy(KeyManagementSystem keyManagementSystem,
                                      @Named("IDPSConnectionProperties") Properties connectionProperties,
                                      CryptoPolicy cryptoPolicy){

        this.keyManagementSystem = keyManagementSystem;

        this.connectionProperties = connectionProperties;

        this.cryptoPolicy = cryptoPolicy;
    }

    public KeyManagementServices getKeyMangementServices() throws EDUSException{

        KeyManagementServices keyManagementServices = null;

        switch (keyManagementSystem){
            case INTUIT:
                keyManagementServices = new IDPS(connectionProperties, cryptoPolicy);
        }

        return keyManagementServices;
    }

    public CryptoPolicy getCryptoPolicy(){

        return this.cryptoPolicy;
    }


}
