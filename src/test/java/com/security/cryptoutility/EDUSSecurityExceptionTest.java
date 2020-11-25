package com.security.cryptoutility;


import org.junit.Test;

import static org.junit.Assert.*;

import java.security.NoSuchAlgorithmException;

/**
 * Created by Raghav S on 8/23/16.
 */
public class EDUSSecurityExceptionTest {

    @Test
    public void setAndReadException(){
        String expMessage = "Test NoSuchAlgorithmException";
        String resultMessage = null;
        Throwable resultCause = null;

        try {

            try {
                throw new NoSuchAlgorithmException(expMessage);
            } catch (NoSuchAlgorithmException nsae) {
                expMessage = nsae.getMessage();
                throw new EDUSException(nsae.getMessage(), nsae);
            }

        }catch(EDUSException ese){
            resultMessage = ese.getMessage();
            resultCause = ese.getCause();
        }

        assertEquals(expMessage, resultMessage);
        assertNotNull(resultCause);
    }
}
