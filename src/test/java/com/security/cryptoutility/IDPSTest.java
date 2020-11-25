package com.security.cryptoutility;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.name.Names;
import com.company.idps.IdpsClient;
import com.company.idps.domain.item.Folder;
import com.company.idps.domain.item.ItemAlreadyExistsException;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;


import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.*;
import static org.hamcrest.Matchers.not;

/**
 * Created by cloudera on 10/24/16.
 */
public class IDPSTest {

    private KeyManagementServices idps;

    private IdpsClient idpsClient;

    private final String API_KEY_ID = "v2-948b8e506b941";

    private final String API_SECRET_KEY = "/home/cloudera/.idps/key_v2-948b8e506b941.pem";

    private final String ENDPOINT = "IDEA-Trinity-Playground-HCGIWCXBZE0E.pd.idps.a.com";

    private final String FOLDERNAME = "edusunittest";


    public class IDPSTestModule extends AbstractModule{

        private Properties connectionProperties;

        public IDPSTestModule(Properties connectionProperties){

            this.connectionProperties = connectionProperties;
        }


        public void configure(){

            bind(Properties.class)
                    .annotatedWith(Names.named("IDPSConnectionProperties"))
                    .toInstance(this.connectionProperties);


            bind(CryptoPolicy.Algorithm.class).toInstance(CryptoPolicy.Algorithm.AES_CBC_HMACSHA256);

            bind(CryptoPolicy.KeySize.class)
                    .annotatedWith(Names.named("EncryptionKeySize")).toInstance(CryptoPolicy.KeySize.BITS_128);

            bind(CryptoPolicy.KeySize.class)
                    .annotatedWith(Names.named("MACKeySize"))
                    .toInstance(CryptoPolicy.KeySize.BITS_256);

            bind(CryptoPolicy.class).to(DefaultCryptoPolicy.class);

            bind(KeyManagementPolicy.KeyManagementSystem.class)
                    .toInstance(KeyManagementPolicy.KeyManagementSystem.INTUIT);

            bind(KeyManagementPolicy.class).to(DefaultKeyManagementPolicy.class);

            bind(KeyManagementServices.class).to(KeyManagementServicesImpl.class);

        }
    }

    @Before
    public void setup() throws Exception{

        Properties connectionProperties = new Properties();

        connectionProperties.put("api_key_id", API_KEY_ID);

        connectionProperties.put("api_secret_key", API_SECRET_KEY);

        connectionProperties.put("endpoint", ENDPOINT);

        Injector injector =  Guice.createInjector(new IDPSTestModule(connectionProperties));

        idps = injector.getInstance(KeyManagementServices.class);

        idpsClient = IdpsClient.Factory.newInstance(connectionProperties);

        Folder folder = null;

        try {

            idpsClient.createFolder(FOLDERNAME, true);

        } catch (ItemAlreadyExistsException iaee) {

        } catch (Exception e){
            throw e;
        }

    }

    @After
    public void destroy(){

        try {

            Folder folder = idpsClient.getFolder(FOLDERNAME);

            folder.deleteAll();
        } catch(Exception e){

        }
    }


    @Test
    public void testGenerateAndUpdateKey() throws EDUSException{

        assertNotNull(idps);

        idps.generateKey(FOLDERNAME + "/TestKey01");

        byte[] keyBytes = idps.getKeyBytes(FOLDERNAME + "/TestKey01");

        assertNotNull(keyBytes);

        idps.updateKey(FOLDERNAME + "/TestKey01");

        byte[] newKeyBytes = idps.getKeyBytes(FOLDERNAME + "/TestKey01");

        assertNotNull(newKeyBytes);

        assertThat(keyBytes, not(newKeyBytes));
    }

    @Test
    public void testGetRandomBytes() throws EDUSException{

        byte[] oneByte_1 = idps.getRandomBytes(1);
        byte[] oneByte_2 = idps.getRandomBytes(1);
        assertThat(oneByte_1, not(oneByte_2));


        byte[] bytes256_1 = idps.getRandomBytes(256);
        byte[] bytes256_2 = idps.getRandomBytes(256);
        assertThat(bytes256_1, not(bytes256_2));

        byte[] bytes16384_1 = idps.getRandomBytes(16384);
        byte[] bytes16384_2 = idps.getRandomBytes(16834);
        assertThat(bytes16384_1, not(bytes16384_2));

    }


    @Test
    public void testEncryptAndDecryptKey() throws EDUSException{

        String keyId = FOLDERNAME + "/TestKeK01";
        byte[] keyblob = idps.getRandomBytes(512);

        idps.generateKey(keyId);

        String encKey =  idps.encrypt(keyId, keyblob);

        byte[] decKeyblob = idps.decrypt(keyId, encKey);

        assertArrayEquals(keyblob, decKeyblob);
    }

    @Test
    public void testGetKeyMgmtSystem() throws EDUSException{

        assertEquals(KeyManagementPolicy.KeyManagementSystem.INTUIT, idps.getKeyManagementSystem());
    }

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testKeyListOperations() throws EDUSException{

        List<String> keyList1 = new ArrayList<String>(5);
        List<String> keyList2 = new ArrayList<String>(5);

        for(int iter = 0; iter < 5; iter++){
            keyList1.add(iter, FOLDERNAME + "/TestKey" + Integer.toString(iter));
        }

        for(int iter = 0; iter < 5; iter++){
            keyList2.add(iter, FOLDERNAME + "/TestKey" + Integer.toString(iter+5));
        }


        try {
            idps.loadKeyList(keyList1);
        }catch (Exception e){
            assertThat(e, instanceOf(EDUSException.class));
        }

        idps.generateKeyList(keyList1);
        idps.loadKeyList(keyList1);

        try{
            idps.loadKeyList(keyList2);
        }catch (Exception e){
            assertThat(e, instanceOf(EDUSException.class));
        }

        idps.generateKeyList(keyList2);
        idps.loadKeyList(keyList2);

        List<byte[]> keyList2Val = new ArrayList<byte[]>(5);
        for(int iter = 0; iter < 5; iter++){
            keyList2Val.add(iter, idps.getKeyBytes(FOLDERNAME + "/TestKey" + Integer.toString(iter+5)));
        }

        idps.updateKeyList();
        List<byte[]> keyList2Val_2 = new ArrayList<byte[]>(5);
        for(int iter = 0; iter < 5; iter++){
            assertThat(keyList2Val.get(iter),
                    not(idps.getKeyBytes(FOLDERNAME + "/TestKey" + Integer.toString(iter+5))) );
        }



    }
}
