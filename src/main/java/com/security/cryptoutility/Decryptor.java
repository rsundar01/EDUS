package com.security.cryptoutility;


/**
 * Decryptor interface describes methods to perform envelope decryption. initialize() method must be called by
 * clients to jump start the internal crypto and key management services engine. The initialize() method has the
 * corresponding uninitalize() method that does the reverse operation of shutting down the internal engines
 *
 * Created on 2016/07/07
 *
 * @author  Raghav S
 * @version 2.0
 * @since   2016-07-07
 */


public interface Decryptor {

    /**
     * intialize() jump starts the internal engines and must called once before invoking other methods
     * @throws EDUSException
     */
    public void initialize() throws EDUSException;

    /**
     * uninitialize() shutsdown the internal engines and must be called by applications before shutdown
     * @throws EDUSException
     */
    public void uninitialize() throws EDUSException;

    /**
     * envelopeDecrypt() envelope decrypts the message provided as input. Envelope decryption means the give message
     * will be searched for the encrypted data key(DK) and will be decrypted with the key encryption key used to
     * encrypt the DK. The resulting DK will be used to decrypt the encrypted data
     * @param message data to be decrypted
     * @return returns the decrypted data bytes
     * @throws EDUSException
     */
    public byte[] envelopeDecrypt(MessageProtoc.Message message) throws EDUSException;

}
