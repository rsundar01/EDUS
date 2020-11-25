package com.security.cryptoutility;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ArrayBlockingQueue;

/**
 * Created by cloudera on 11/10/16.
 */
class RandomPool implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(RandomPool.class);

    private final int CAPACITY = 5;

    private final int BLOCKSIZE = 32;

    private ArrayBlockingQueue<byte[]> randomQueue;

    private KeyManagementServices keyManagementServices;

    private RandomSource randomSource;

    public RandomPool(RandomSource randomSource){

        randomQueue = new ArrayBlockingQueue<byte[]>(CAPACITY, true);

        this.randomSource = randomSource;

    }

    public void run() {

        while(true){
            try {

                LOGGER.debug("Adding random bytes to queue from source " + randomSource.getRandomSource());

                byte[] randomBytes = randomSource.getSeed(BLOCKSIZE);

                randomQueue.put(randomBytes);

                synchronized (this) {

                    notify();

                }

                Thread.sleep(100);

            }catch (Exception e){
                return;
            }
        }

    }

    public synchronized byte[] getNextBytes(){

        byte[] returnBytes = null;

        try {

            LOGGER.info("Get random bytes from " + randomSource.getRandomSource());

            if(randomQueue.peek() == null){

                LOGGER.debug("Waiting for random bytes from " + randomSource.getRandomSource());

                wait();

                LOGGER.debug("Wait is over. Now proceeding");
            }

            returnBytes = randomQueue.take();

            LOGGER.info("Get random bytes from " + randomSource.getRandomSource() + " successful");

        } catch (Exception e){}

        return returnBytes;
    }

    /*public byte[] getNextBytes(){

        byte[] returnBytes = null;

        try {

            LOGGER.info("Get random bytes from " + randomSource.getRandomSource());

            if(randomQueue.peek() != null) {

                returnBytes = randomQueue.take();

                LOGGER.info("Get random bytes from " + randomSource.getRandomSource() + " successful");
            }

        } catch (Exception e){}

        return returnBytes;
    }*/

    /*public int compareTo(PriorityRunnable otherRunnable){

        return this.priority - otherRunnable.getPriority();
    }

    public void setPriority(int priority){

        this.priority = priority;
    }

    public int getPriority(){

        return priority;
    }*/
}
