package com.security.cryptoutility;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.name.Names;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.*;

/**
 * Created by cloudera on 10/20/16.
 */
public class CryptoPolicyTest {

    private CryptoPolicy cryptoPolicy;

    private List<CryptoPolicy.Algorithm> list;

    private CryptoPolicy.Algorithm algorithmList[];

    {
        algorithmList = CryptoPolicy.Algorithm.values();

        list = Arrays.asList(algorithmList);
    }


    class CryptoPolicyTestModule extends AbstractModule{

        private CryptoPolicy.Algorithm algorithm;

        private CryptoPolicy.KeySize encryptionKeySize;

        private CryptoPolicy.KeySize macKeySize;


        CryptoPolicyTestModule(CryptoPolicy.Algorithm algorithm,
                               CryptoPolicy.KeySize encryptionKeySize,
                               CryptoPolicy.KeySize macKeySize){

            this.algorithm = algorithm;

            this.encryptionKeySize = encryptionKeySize;

            this.macKeySize = macKeySize;

        }

        @Override
        protected void configure(){

            bind(CryptoPolicy.Algorithm.class).toInstance(algorithm);

            bind(CryptoPolicy.KeySize.class)
                    .annotatedWith(Names.named("EncryptionKeySize")).toInstance(encryptionKeySize);

            bind(CryptoPolicy.KeySize.class).annotatedWith(Names.named("MACKeySize")).toInstance(macKeySize);

            bind(CryptoPolicy.class).to(DefaultCryptoPolicy.class);
        }
    }


    @Before
    public void setup() {

        Random random = new Random();

        int offset = random.nextInt(this.algorithmList.length);

        Injector injector = Guice.createInjector(this.new CryptoPolicyTestModule(algorithmList[offset],
                CryptoPolicy.KeySize.BITS_256, CryptoPolicy.KeySize.BITS_256));

        cryptoPolicy =  injector.getInstance(CryptoPolicy.class);

    }


    @Test
    public void testGetAlgorithm(){

        CryptoPolicy.Algorithm algorithm = cryptoPolicy.getAlgorithm();

        assertTrue(list.contains(algorithm));

    }

    @Test
    public void testAllCipherAndMac(){

        for(int iter = 0; iter < algorithmList.length; iter++) {

            CryptoPolicy cryptoPolicyLocal = new DefaultCryptoPolicy(algorithmList[iter],
                    CryptoPolicy.KeySize.BITS_128, CryptoPolicy.KeySize.BITS_128);

            switch(algorithmList[iter]) {
                case AES_CBC_HMACSHA1:{
                    assertEquals(cryptoPolicyLocal.getCipherTranformation(), "AES/CBC/PKCS5Padding");
                    assertEquals(cryptoPolicyLocal.getMacAlgorithmString(), "HmacSHA1");
                    assertEquals(cryptoPolicyLocal.getEncryptionAlgorithmString(), "AES");
                    assertEquals(cryptoPolicyLocal.getMode(), "CBC");
                    assertEquals(cryptoPolicyLocal.getPadding(), "PKCS5Padding");
                    assertEquals(cryptoPolicyLocal.getAlgorithm(), CryptoPolicy.Algorithm.AES_CBC_HMACSHA1);
                    assertEquals(cryptoPolicyLocal.getBlockSize(), 16);
                    assertEquals(cryptoPolicyLocal.getEncryptKeySize(), 16);
                    assertEquals(cryptoPolicyLocal.getMacKeySize(), 16);
                    break;
                }
                case AES_CBC_HMACSHA256: {
                    assertEquals(cryptoPolicyLocal.getCipherTranformation(), "AES/CBC/PKCS5Padding");
                    assertEquals(cryptoPolicyLocal.getMacAlgorithmString(), "HmacSHA256");
                    assertEquals(cryptoPolicyLocal.getEncryptionAlgorithmString(), "AES");
                    assertEquals(cryptoPolicyLocal.getMode(), "CBC");
                    assertEquals(cryptoPolicyLocal.getPadding(), "PKCS5Padding");
                    assertEquals(cryptoPolicyLocal.getAlgorithm(), CryptoPolicy.Algorithm.AES_CBC_HMACSHA256);
                    assertEquals(cryptoPolicyLocal.getBlockSize(), 16);
                    assertEquals(cryptoPolicyLocal.getEncryptKeySize(), 16);
                    assertEquals(cryptoPolicyLocal.getMacKeySize(), 16);
                    break;
                }
                case AES_GCM_HMACSHA1:{
                    assertEquals(cryptoPolicyLocal.getCipherTranformation(), "AES/GCM/NoPadding");
                    assertEquals(cryptoPolicyLocal.getMacAlgorithmString(), "HmacSHA1");
                    assertEquals(cryptoPolicyLocal.getEncryptionAlgorithmString(), "AES");
                    assertEquals(cryptoPolicyLocal.getMode(), "GCM");
                    assertEquals(cryptoPolicyLocal.getPadding(), "NoPadding");
                    assertEquals(cryptoPolicyLocal.getAlgorithm(), CryptoPolicy.Algorithm.AES_GCM_HMACSHA1);
                    assertEquals(cryptoPolicyLocal.getBlockSize(), 16);
                    assertEquals(cryptoPolicyLocal.getEncryptKeySize(), 16);
                    assertEquals(cryptoPolicyLocal.getMacKeySize(), 16);
                    break;
                }
                case AES_GCM_HMACSHA256: {
                    assertEquals(cryptoPolicyLocal.getCipherTranformation(), "AES/GCM/NoPadding");
                    assertEquals(cryptoPolicyLocal.getMacAlgorithmString(), "HmacSHA256");
                    assertEquals(cryptoPolicyLocal.getEncryptionAlgorithmString(), "AES");
                    assertEquals(cryptoPolicyLocal.getMode(), "GCM");
                    assertEquals(cryptoPolicyLocal.getPadding(), "NoPadding");
                    assertEquals(cryptoPolicyLocal.getAlgorithm(), CryptoPolicy.Algorithm.AES_GCM_HMACSHA256);
                    assertEquals(cryptoPolicyLocal.getBlockSize(), 16);
                    assertEquals(cryptoPolicyLocal.getEncryptKeySize(), 16);
                    assertEquals(cryptoPolicyLocal.getMacKeySize(), 16);
                    break;
                }
                case AES_CBC_NONE:{
                    assertEquals(cryptoPolicyLocal.getCipherTranformation(), "AES/CBC/PKCS5Padding");
                    assertEquals(cryptoPolicyLocal.getMacAlgorithmString(), "");
                    assertEquals(cryptoPolicyLocal.getEncryptionAlgorithmString(), "AES");
                    assertEquals(cryptoPolicyLocal.getMode(), "CBC");
                    assertEquals(cryptoPolicyLocal.getPadding(), "PKCS5Padding");
                    assertEquals(cryptoPolicyLocal.getAlgorithm(), CryptoPolicy.Algorithm.AES_CBC_NONE);
                    assertEquals(cryptoPolicyLocal.getBlockSize(), 16);
                    assertEquals(cryptoPolicyLocal.getEncryptKeySize(), 16);
                    assertEquals(cryptoPolicyLocal.getMacKeySize(), 16);
                    break;
                }
                case HMACSHA1:{
                    assertEquals(cryptoPolicyLocal.getCipherTranformation(), "");
                    assertEquals(cryptoPolicyLocal.getMacAlgorithmString(), "HmacSHA1");
                    assertEquals(cryptoPolicyLocal.getEncryptionAlgorithmString(), "");
                    assertEquals(cryptoPolicyLocal.getMode(), "");
                    assertEquals(cryptoPolicyLocal.getPadding(), "");
                    assertEquals(cryptoPolicyLocal.getAlgorithm(), CryptoPolicy.Algorithm.HMACSHA1);
                    assertEquals(cryptoPolicyLocal.getBlockSize(), 16);
                    assertEquals(cryptoPolicyLocal.getEncryptKeySize(), 16);
                    assertEquals(cryptoPolicyLocal.getMacKeySize(), 16);
                    break;
                }
                case HMACSHA256: {
                    assertEquals(cryptoPolicyLocal.getCipherTranformation(), "");
                    assertEquals(cryptoPolicyLocal.getMacAlgorithmString(), "HmacSHA256");
                    assertEquals(cryptoPolicyLocal.getEncryptionAlgorithmString(), "");
                    assertEquals(cryptoPolicyLocal.getMode(), "");
                    assertEquals(cryptoPolicyLocal.getPadding(), "");
                    assertEquals(cryptoPolicyLocal.getAlgorithm(), CryptoPolicy.Algorithm.HMACSHA256);
                    assertEquals(cryptoPolicyLocal.getBlockSize(), 16);
                    assertEquals(cryptoPolicyLocal.getEncryptKeySize(), 16);
                    assertEquals(cryptoPolicyLocal.getMacKeySize(), 16);
                    break;
                }

            }

            assertEquals(cryptoPolicyLocal.getJCEProvider(), "SunJCE");
            assertEquals(cryptoPolicyLocal.getSecureRandomAlgo(), "NativePRNGBlocking");
        }


        assertEquals(cryptoPolicy.getBlockSize(), 16);
        assertEquals(cryptoPolicy.getEncryptKeySize(), 32);
        assertEquals(cryptoPolicy.getMacKeySize(), 32);
    }
}
