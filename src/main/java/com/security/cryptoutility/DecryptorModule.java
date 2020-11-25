package com.security.cryptoutility;

import com.google.inject.AbstractModule;
import com.google.inject.Singleton;
import com.google.inject.name.Names;

import java.util.Properties;

/**
 * Created by Raghav S on 11/15/16.
 */
class DecryptorModule extends AbstractModule {

    private CryptoPolicy.Algorithm algorithm;

    private KeyManagementPolicy.KeyManagementSystem keyManagementSystem;

    private Properties connectionProperties;

    private CryptoPolicy.KeySize encryptionKeySize;

    private CryptoPolicy.KeySize macKeySize;

    public DecryptorModule( CryptoPolicy.Algorithm algorithm,
                            CryptoPolicy.KeySize encryptionKeySize,
                            CryptoPolicy.KeySize macKeySize,
                            KeyManagementPolicy.KeyManagementSystem keyManagementSystem,
                            Properties connectionProperties){

        this.algorithm = algorithm;

        this.encryptionKeySize = encryptionKeySize;

        this.macKeySize = macKeySize;

        this.keyManagementSystem = keyManagementSystem;

        this.connectionProperties = connectionProperties;

    }

    @Override
    protected void  configure(){

        bind(Properties.class)
                .annotatedWith(Names.named("IDPSConnectionProperties"))
                .toInstance(this.connectionProperties);

        bind(CryptoPolicy.Algorithm.class).toInstance(algorithm);

        bind(CryptoPolicy.KeySize.class).annotatedWith(Names.named("EncryptionKeySize"))
                .toInstance(this.encryptionKeySize);

        bind(CryptoPolicy.KeySize.class).annotatedWith(Names.named("MACKeySize"))
                .toInstance(this.macKeySize);

        bind(CryptoPolicy.class).to(DefaultCryptoPolicy.class);

        bind(KeyManagementPolicy.KeyManagementSystem.class)
                .toInstance(KeyManagementPolicy.KeyManagementSystem.INTUIT);

        bind(KeyManagementPolicy.class).to(DefaultKeyManagementPolicy.class);

        bind(PRNGenerator.class)
                .to(PRNGeneratorImpl.class);

        bind(KeyManagementServices.class).to(KeyManagementServicesImpl.class);

        bind(CryptoServices.class).to(CryptoServicesImpl.class);

        bind(Decryptor.class)
                .to(DecryptorImpl.class).in(Singleton.class);

    }
}

