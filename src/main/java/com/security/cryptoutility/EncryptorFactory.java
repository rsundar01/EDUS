package com.security.cryptoutility;

import com.google.inject.Guice;
import com.google.inject.Injector;

import java.util.Properties;

/**
 * Created by Raghav S on 8/24/16.
 */
public class EncryptorFactory {

    public static Encryptor getInstance(CryptoPolicy.Algorithm algorithm,
                                        CryptoPolicy.KeySize encryptionKeySize,
                                        CryptoPolicy.KeySize macKeySize,
                                        KeyManagementPolicy.KeyManagementSystem keyManagementSystem,
                                        Properties connectionProperties){

        Injector injector = Guice.createInjector(
                new EncryptorModule(algorithm, encryptionKeySize, macKeySize, keyManagementSystem, connectionProperties));

        Encryptor encryptor = injector.getInstance(EncryptorImpl.class);

        return encryptor;
    }
}
