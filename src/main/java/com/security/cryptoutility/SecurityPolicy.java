package com.security.cryptoutility;

import com.google.inject.Inject;

/**
 * Created by cloudera on 10/15/16.
 */
class SecurityPolicy {

    private DefaultCryptoPolicy cryptoPolicy;

    private DefaultKeyManagementPolicy keyManagementPolicy;

    @Inject
    public SecurityPolicy(DefaultCryptoPolicy cryptoPolicy, DefaultKeyManagementPolicy keyManagementPolicy){

        this.cryptoPolicy = cryptoPolicy;

        this.keyManagementPolicy = keyManagementPolicy;
    }

    public DefaultCryptoPolicy getCryptoPolicy(){
        return cryptoPolicy;
    }

    public DefaultKeyManagementPolicy getKeyManagementPolicy(){
        return keyManagementPolicy;
    }
}
