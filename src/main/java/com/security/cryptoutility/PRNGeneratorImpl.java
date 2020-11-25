package com.security.cryptoutility;

import com.google.inject.Inject;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.concurrent.*;

/**
 * Created by Raghav S on 9/20/16.
 */
class PRNGeneratorImpl implements PRNGenerator {

    private static final Logger LOGGER = LoggerFactory.getLogger(PRNGeneratorImpl.class);

    private CryptoPolicy cryptoPolicy = null;

    private KeyManagementServices keyManagementServices = null;

    private RandomSource localRandomSource;

    private RandomSource kmsRandomSource;

    private RandomPool localRandomPool;

    private RandomPool kmsRandomPool;

    ExecutorService threadPool;

    //ThreadPoolExecutor threadPool;

    //BlockingQueue<Runnable> workQueue;

    private SP800SecureRandomBuilder sp800SecureRandomBuilder;

    private SecureRandom secureRandomSP800;

    private boolean isInitialized = false;

    final private int seedSchedule = 10000;

    private int seedScheduleCounter = 0;

    final private int seedSizeBytes = 32;

    @Inject
    public PRNGeneratorImpl(CryptoPolicy cryptoPolicy,
                            KeyManagementServices keyManagementServices) throws EDUSException{

        this.cryptoPolicy = cryptoPolicy;

        this.keyManagementServices = keyManagementServices;

        //this.localRandomSourceThread = Executors.newSingleThreadExecutor();

        //this.kmsRandomSourceThread = Executors.newSingleThreadExecutor();

        //threadPool = Executors.newFixedThreadPool(2);

        threadPool = Executors.newCachedThreadPool();

        //workQueue = new PriorityBlockingQueue<Runnable>(10);

        //threadPool = new ThreadPoolExecutor(2, 4, 10, TimeUnit.MILLISECONDS, workQueue);

        //threadPool.prestartAllCoreThreads();

        sp800SecureRandomBuilder = new SP800SecureRandomBuilder();

    }

    public void initialize() throws EDUSException{

        LOGGER.info("Initializing PRNGenerator - Default");

        this.localRandomSource = new DefaultRandomSource(cryptoPolicy);

        this.kmsRandomSource = new KMSRandomSource(keyManagementServices);

        initializeSecureRandom();

        LOGGER.info("Initializing local random source thread");

        localRandomPool = new RandomPool(localRandomSource);

        threadPool.submit(localRandomPool);

        LOGGER.info("Initializing kms random source thread");

        kmsRandomPool = new RandomPool(kmsRandomSource);

        threadPool.submit(kmsRandomPool);

        isInitialized = true;

        LOGGER.info("PRNGenerator Initialized");

    }

    private void initializeSecureRandom() throws EDUSException{

        LOGGER.info("Initializing secure random engine");

        Digest digestSHA256 = new SHA256Digest();

        Mac mac = new HMac(digestSHA256);

        LOGGER.info("Generate nonce");

        byte[] nonce = kmsRandomSource.getSeed(seedSizeBytes);

        LOGGER.info("Generate initial seed");

        byte[] seed = mixSeedBytes(localRandomSource.getSeed(seedSizeBytes),
                                    kmsRandomSource.getSeed(seedSizeBytes));

        LOGGER.info("Instantiate NIST sp800 DRBG");

        secureRandomSP800 = sp800SecureRandomBuilder.buildHMAC(mac, nonce,  false);

        //setSeedBytesPrivate(seedSizeBytes);
        secureRandomSP800.setSeed(seed);
    }

    private void checkInitialization() throws EDUSException{

        if(!isInitialized){
            throw new EDUSException("PRNGGenerator is not initialized");
        }
    }

    public byte[] getRandomBytes(int size) throws EDUSException{

        checkInitialization();

        byte[] randomBytes = new byte[size];

        if(seedScheduleCounter > seedSchedule){

            LOGGER.info("Reseeding the SP800 Random Generator");

            setSeedBytesPrivate(seedSizeBytes);

            secureRandomSP800.nextBytes(randomBytes);

            resetSeedScheduleCounter();

        } else {

            secureRandomSP800.nextBytes(randomBytes);

            incrementSeedScheduleCounter();

        }

        return randomBytes;

    }

    private void resetSeedScheduleCounter(){

        seedScheduleCounter = 0;
    }

    private void incrementSeedScheduleCounter(){

        seedScheduleCounter++;
    }

    public void setSeedBytes(int size) throws EDUSException{

        checkInitialization();

        setSeedBytesPrivate(size);

        resetSeedScheduleCounter();

    }

    private void setSeedBytesPrivate(int size) throws EDUSException{

        byte[] seed = readAndMixEntropies(size);

        secureRandomSP800.setSeed(seed);

    }

    private byte[] readAndMixEntropies(int size) {

        LOGGER.debug("Get random from local");

        byte[] randomBytesSource1 = getNextBytes(localRandomPool);

        LOGGER.debug("Get random from kms");

        byte[] randomBytesSource2 = getNextBytes(kmsRandomPool);

        return mixSeedBytes(randomBytesSource1, randomBytesSource2);
    }


    private byte[] mixSeedBytes(byte[] buffer1, byte[] buffer2){

        byte[] randomBytes = null;

        //check array size
        if(buffer1.length != buffer2.length){

            return randomBytes;
        }

        int iter = 0;

        randomBytes = new byte[buffer1.length];

        for( byte b : buffer1){

            randomBytes[iter] = (byte) (b ^ buffer2[iter++]);
        }

        return randomBytes;
    }


    private byte[] getNextBytes(RandomPool randomPool){

        int index = 0;

        int copyIndex = 0;

        LOGGER.debug("Get random next bytes");

        byte[] buffer = randomPool.getNextBytes();

        LOGGER.debug("received random bytes");

        return buffer;
    }


    public void uninitialize() throws EDUSException{

        try {

            if( !threadPool.isShutdown() ){

                threadPool.shutdownNow();

            }

            isInitialized = false;

        } catch (Exception e){

            throw new EDUSException(e);
        }

    }


}
