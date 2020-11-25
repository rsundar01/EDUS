package com.security.cryptoutility;

import com.google.inject.Guice;
import com.google.inject.Injector;

import java.util.Properties;

/**
 * Created by cloudera on 11/15/16.
 */
public class DecryptorFactory {

    public static Decryptor getInstance(CryptoPolicy.Algorithm algorithm,
                                        CryptoPolicy.KeySize encryptionKeySize,
                                        CryptoPolicy.KeySize macKeySize,
                                        KeyManagementPolicy.KeyManagementSystem keyManagementSystem,
                                        Properties connectionProperties){

        Injector injector = Guice.createInjector(
                new DecryptorModule(algorithm, encryptionKeySize, macKeySize, keyManagementSystem, connectionProperties));

        Decryptor decryptor = injector.getInstance(Decryptor.class);

        return decryptor;
    }
}

