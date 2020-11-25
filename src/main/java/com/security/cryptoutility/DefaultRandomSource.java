package com.security.cryptoutility;

import com.google.inject.Inject;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by cloudera on 11/10/16.
 */
class DefaultRandomSource implements RandomSource {

    private SecureRandom secureRandom = null;

    private CryptoPolicy cryptoPolicy = null;

    @Inject
    public DefaultRandomSource(CryptoPolicy cryptoPolicy) throws EDUSException{


        try {

            this.cryptoPolicy = cryptoPolicy;

            secureRandom = SecureRandom.getInstance(cryptoPolicy.getSecureRandomAlgo());

        }catch (NoSuchAlgorithmException nsae){

            throw new EDUSException(nsae);
        }

    }

    public byte[] getSeed(int size) throws EDUSException{

        return secureRandom.generateSeed(size);

    }

    public String getRandomSource() throws EDUSException{

        return cryptoPolicy.getSecureRandomAlgo();
    }
}
