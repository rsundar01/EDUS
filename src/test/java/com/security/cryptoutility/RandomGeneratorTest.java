package com.security.cryptoutility;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.name.Names;
import com.company.idps.IdpsClient;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Properties;

import static org.hamcrest.Matchers.not;

import static org.junit.Assert.*;

/**
 * Created by cloudera on 11/11/16.
 */
public class RandomGeneratorTest {

    private KeyManagementServices idps;

    private IdpsClient idpsClient;

    private final String API_KEY_ID = "v2-948b8e506b941";

    private final String API_SECRET_KEY = "/home/cloudera/.idps/key_v2-948b8e506b941.pem";

    private final String ENDPOINT = "IDEA-Trinity-Playground-HCGIWCXBZE0E.pd.idps.a.company.com";

    private final String FOLDERNAME = "edusunittest";

    private RandomSource randomSource1, randomSource2;

    private RandomPool randomPool1, randomPool2;

    private PRNGenerator prnGenerator;

    public class KMSRandomSourceTestModule extends AbstractModule{

        private Properties connectionProperties;

        public KMSRandomSourceTestModule(Properties connectionProperties){

            this.connectionProperties = connectionProperties;
        }

        public void configure(){

            bind(Properties.class)
                    .annotatedWith(Names.named("IDPSConnectionProperties"))
                    .toInstance(this.connectionProperties);


            //bind(CryptoPolicy.Algorithm.class).toInstance(CryptoPolicy.Algorithm.AES_CBC_HMACSHA256);

            //bind(CryptoPolicy.KeySize.class)
            //        .annotatedWith(Names.named("EncryptionKeySize")).toInstance(CryptoPolicy.KeySize.BITS_128);

            //bind(CryptoPolicy.KeySize.class)
            //        .annotatedWith(Names.named("MACKeySize"))
            //        .toInstance(CryptoPolicy.KeySize.BITS_256);

            //bind(CryptoPolicy.class).to(DefaultCryptoPolicy.class);

            bind(CryptoPolicy.class).to(MockCryptoPolicy.class);

            bind(KeyManagementPolicy.KeyManagementSystem.class)
                    .toInstance(KeyManagementPolicy.KeyManagementSystem.INTUIT);

            bind(KeyManagementPolicy.class).to(DefaultKeyManagementPolicy.class);

            bind(KeyManagementServices.class).to(KeyManagementServicesImpl.class);

            bind(PRNGenerator.class).to(PRNGeneratorImpl.class);
        }
    }


    @Before
    public void setup() throws Exception{

        Properties connectionProperties = new Properties();

        connectionProperties.put("api_key_id", API_KEY_ID);

        connectionProperties.put("api_secret_key", API_SECRET_KEY);

        connectionProperties.put("endpoint", ENDPOINT);

        Injector injector =  Guice.createInjector(
                new KMSRandomSourceTestModule(connectionProperties));

        idps = injector.getInstance(KeyManagementServices.class);

        randomSource1 = new KMSRandomSource(idps);

        randomSource2 = new DefaultRandomSource(injector.getInstance(CryptoPolicy.class));

        randomPool1 = new RandomPool(randomSource1);

        randomPool2 = new RandomPool(randomSource2);

        prnGenerator = injector.getInstance(PRNGenerator.class);

    }

    @Test
    public void testIDPSSeedGeneration() throws EDUSException{

        int size = 2;

        byte[] randomData1 = new byte[size];

        Arrays.fill(randomData1, (byte)0);

        byte[] randomData2 = new byte[size];

        Arrays.fill(randomData2, (byte)0);

        assertArrayEquals(randomData1, randomData2);

        randomData1 = randomSource1.getSeed(size);

        assertNotNull(randomData1);

        randomData2 = randomSource1.getSeed(size);

        assertNotNull(randomData2);

        assertThat(randomData1, not(randomData2));

    }

    @Test
    public void testRandomPool() throws EDUSException, InterruptedException{

        Thread poolThread = new Thread(randomPool1);

        poolThread.start();

        byte[] bytes1 = randomPool1.getNextBytes();

        byte[] bytes2 = randomPool1.getNextBytes();

        assertNotNull(bytes1);

        assertNotNull(bytes2);

        assertEquals(bytes1.length, 32);

        assertEquals(bytes2.length, 32);

        assertThat(bytes1, not(bytes2));

        poolThread.interrupt();

        poolThread.join();


    }

    @Test
    public void testDevRandomSeedGeneration() throws EDUSException{

        int size = 2;

        byte[] randomData1 = new byte[size];

        Arrays.fill(randomData1, (byte)0);

        byte[] randomData2 = new byte[size];

        Arrays.fill(randomData2, (byte)0);

        assertArrayEquals(randomData1, randomData2);

        randomData1 = randomSource2.getSeed(size);

        assertNotNull(randomData1);

        randomData2 = randomSource2.getSeed(size);

        assertNotNull(randomData2);

        assertThat(randomData1, not(randomData2));


    }

    @Test
    public void testPRNGenerator() throws EDUSException{

        prnGenerator.initialize();

        byte[] randomBytes1 =  prnGenerator.getRandomBytes(32);

        byte[] randomBytes2 =  prnGenerator.getRandomBytes(32);

        assertNotNull(randomBytes1);

        assertNotNull(randomBytes2);

        assertThat(randomBytes1, not(randomBytes2));

        prnGenerator.uninitialize();

    }

}
