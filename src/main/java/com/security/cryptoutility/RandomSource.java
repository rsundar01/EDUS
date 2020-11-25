package com.security.cryptoutility;

/**
 * Created by cloudera on 11/10/16.
 */

interface RandomSource {

    public byte[] getSeed(int size) throws EDUSException;

    public String getRandomSource() throws EDUSException;
}
