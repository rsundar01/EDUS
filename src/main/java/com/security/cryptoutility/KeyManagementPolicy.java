package com.security.cryptoutility;

/**
 * Key management policy defines the key management system attributes
 *
 * @author  Raghav S
 * @version 1.0
 * @since   2016-10-17
 */
public interface KeyManagementPolicy {

    /**
     * KeyManagementSystem lists available key management systems that can be used
     */
    public enum KeyManagementSystem{
        INTUIT /*, AWSKMS*/
    }

    /**
     * Returns the KeyManagementServices engine
     * @return
     * @throws EDUSException
     */
    public KeyManagementServices getKeyMangementServices() throws EDUSException;

    /**
     * Returns the crypto policy being used
     * @return
     */
    public CryptoPolicy getCryptoPolicy();
}
