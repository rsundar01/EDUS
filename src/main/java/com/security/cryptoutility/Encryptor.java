package com.security.cryptoutility;

import java.util.List;


/**
 * Encryptor interface describes methods to perform envelope encryption and methods supporting the core
 * operation. initialize() method must be called by clients to jump start the internal crypto and key
 * management services engine. The initialize() method has the corresponding uninitalize() method
 * that does the reverse operation of shutting down the internal engine
 *
 * Created on 2016/07/07
 *
 * @author  Raghav S
 * @version 2.0
 * @since   2017-08-23
 */

public interface Encryptor {

    /**
     * generateKEK() method generates new key encryption key in the underlying key management system with the
     * String parameter as the Identifier. If the key encryption key is already present in the key management system
     * then this method will throw an EDUSException
     *
     * @param kekID Key encryption key ID
     * @throws EDUSException if the key already exists or the underlying key management system throws an exception
     */
    public void generateKEK(String kekID) throws EDUSException;

    /**
     * initialize() method is the first method that must be called. This method initializes the internal crypto
     * services and key management services engine. Calling other methods in this class ahead of initialize()
     * will result in the method throwing EDUSException
     *
     * @throws EDUSException
     */
    public void initialize() throws EDUSException;

    /**
     * initializeKEKPool() method initializes a list of key encryption keys. This set of keys will be used by the
     * method envelopeEncrypteWithRandomKek(). The list of keys given as parameters must be present in the underlying
     * key management system if the generateKeys parameter is set to false otherwise the method call will result
     * in an EDUSException. If one or more keys in the list is not present in the key management system and
     * if the generateKeys parameter is true then the method will attempt to generate the key in the key management
     * system
     *
     * @param kekPool list of key encryption keys
     * @param generateKeys flag to generates keys specified in the list if not already present in the
     * key management system
     * @throws EDUSException
     */
    public void initializeKEKPool(List<String> kekPool, boolean generateKeys) throws EDUSException;

    /**
     * envelopeEncryptWithKek() envelope encrypts the given data bytes with the given key encryption key. Envelope
     * encryption means a Data Key(DK) is generated for each message and is used to encrypt the message. The DK
     * will in turn be encrypted with a Key encryption key and will be placed along with the message.
     * @param kekID ID of the key encryption key used in the envelope encryption
     * @param dataBytes data to be encrypted
     * @throws EDUSException
     */
    public MessageProtoc.Message envelopeEncryptWithKek(String kekID, byte[] dataBytes) throws EDUSException;

    /**
     * envelopeEncryptWithRandomKek() envelope encrypts the given data byte using a key encryption key chosen
     * at random.
     * note: initializeKEKPool() must be called once before calling this method
     * @param dataBytes data to be encrypted
     * @return returns the envelope message
     * @throws EDUSException
     */
    public MessageProtoc.Message envelopeEncryptWithRandomKek(byte[] dataBytes) throws EDUSException;

    /**
     * unintialize() method shutsdown the crypto services and key management services engine. This method must be
     * called at the very end before application shutdown.
     * @throws EDUSException
     */
    public void uninitialize() throws EDUSException;

}
