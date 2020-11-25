package com.security.cryptoutility;

import static org.junit.Assert.*;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.name.Names;
/*import com.idps.IdpsClient;
import com.idps.domain.item.Folder;
import com.idps.domain.item.ItemAlreadyExistsException;*/
import com.security.cryptoutility.message.MessageProtoc;
import org.junit.After;
import org.junit.Test;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.*;
import java.util.Properties;

/**
 * Created by Raghav S on 6/29/16.
 */
public class EncryptorTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(EncryptorTest.class);

    private final String API_KEY_ID = "v2-948b8e506b941";

    private final String API_SECRET_KEY = "/home/cloudera/.idps/key_v2-948b8e506b941.pem";

    private final String ENDPOINT = "IDEA-Trinity-Playground-HCGIWCXBZE0E.pd.idps.a.com";

    private Encryptor encryptor;

    private Decryptor decryptor;

    final private static int BUFFER_SIZE = 8192;

    final private String TESTFILE = "TestFile_1MB";

    private File testFile = null;

    private final String FOLDERNAME = "edusunittest";

    //private IdpsClient idpsClient;

    class EncryptorTestModule extends AbstractModule {

        private CryptoPolicy.Algorithm algorithm;

        private Properties connectionProperties;

        private CryptoPolicy.KeySize encryptionKeySize;

        private CryptoPolicy.KeySize macKeySize;

        public EncryptorTestModule(Properties connectionProperties){

            this.connectionProperties = connectionProperties;

        }

        @Override
        protected  void configure() {

            bind(Properties.class)
                    .annotatedWith(Names.named("IDPSConnectionProperties"))
                    .toInstance(this.connectionProperties);

            bind(CryptoPolicy.class).to(MockCryptoPolicy.class);

            bind(KeyManagementPolicy.KeyManagementSystem.class)
                    .toInstance(KeyManagementPolicy.KeyManagementSystem.INTUIT);

            bind(KeyManagementPolicy.class).to(DefaultKeyManagementPolicy.class);

            bind(KeyManagementServices.class).to(KeyManagementServicesImpl.class);

            bind(PRNGenerator.class).to(PRNGeneratorImpl.class);

            bind(CryptoServices.class).to(CryptoServicesImpl.class);

            bind(Encryptor.class).to(EncryptorImpl.class);

            bind(Decryptor.class).to(DecryptorImpl.class);
        }
    }

    @Before
    public void setup() throws Exception{

        LOGGER.info("Doing setup()");

        Properties connectionProperties = new Properties();

        connectionProperties.put("api_key_id", API_KEY_ID);

        connectionProperties.put("api_secret_key", API_SECRET_KEY);

        connectionProperties.put("endpoint", ENDPOINT);

        Injector injector = Guice.createInjector(this.new EncryptorTestModule(connectionProperties));

        encryptor = injector.getInstance(Encryptor.class);

        decryptor = injector.getInstance(Decryptor.class);

        LOGGER.debug("Initializing encryptor");

        encryptor.initialize();

        decryptor.initialize();

        LOGGER.debug("Encryptor initialization completed");

        decryptor = injector.getInstance(Decryptor.class);

        testFile = new File(getClass().getClassLoader().getResource(TESTFILE).getPath());

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
    public void destroy() throws Exception{

        encryptor.uninitialize();

        decryptor.uninitialize();

        Folder folder = idpsClient.getFolder(FOLDERNAME);

        folder.deleteAll();

    }

    @Test
    public void encryptFileTest() throws EDUSException{

        LOGGER.info("Executing encryptFileTest()");

        byte[] fileBytes = readFile(testFile);

        encryptor.generateKEK(FOLDERNAME + "/test_kek_01");

        MessageProtoc.Message message = encryptor.envelopeEncryptWithKek(FOLDERNAME + "/test_kek_01", fileBytes);
        assertNotNull(message);

        byte[] receivedfileBytes = decryptor.envelopeDecrypt(message);
        assertNotNull(receivedfileBytes);

        assertArrayEquals(fileBytes, receivedfileBytes);

    }


    private byte[] readFile(File testFile){

        FileInputStream fis = null;
        ByteArrayOutputStream baos = null;
        byte[] outBytes = null;

        byte[] buffer = new byte[BUFFER_SIZE];


        try {
            fis = new FileInputStream(testFile);
            baos = new ByteArrayOutputStream();

            int readBytes = 0;
            while((readBytes = fis.read(buffer)) != -1){
                baos.write(buffer, 0, readBytes);
            }

            outBytes = baos.toByteArray();
        }catch (FileNotFoundException fne){
            LOGGER.error(fne.getMessage(), fne.getCause());
        }catch (IOException ioe){
            LOGGER.error(ioe.getMessage(), ioe.getCause());
        }finally {
            try{
                fis.close();
                baos.close();
            }catch(IOException ioe){}
        }

        return outBytes;

    }


}
