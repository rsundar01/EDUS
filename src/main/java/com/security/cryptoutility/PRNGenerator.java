package com.security.cryptoutility;

/**
 * Created by cloudera on 9/20/16.
 */
public interface PRNGenerator {

    public void initialize() throws EDUSException;

    public void setSeedBytes(int size) throws EDUSException;

    public byte[] getRandomBytes(int size) throws EDUSException;

    public void uninitialize() throws EDUSException;

}
