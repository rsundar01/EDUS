package com.security.cryptoutility;

/**
 * CryptoPolicy defines the crypto attributes required for the encryption and decryption operations. The CryptoPolicy
 * interface provides methods to get the crypto attributes which will be used as input to perform cryptographic operations
 * This interface defines two interfaces:
 *  1. Algorithm - defines the encryption and mac algorithm to be used for the cryptographic operations
 *  2. KeySize - defines the key size to be used for the cryptographic operation using the algorithm selected
 *
 * @author  Raghav S
 * @version 2.0
 * @since   2016-07-01
 */


public interface CryptoPolicy {

    /**
     * List of algorithms allowed by the policy. Each element defines an encryption and a mac algorithm along with
     * the modes of operation
     *
     * @author  Raghav S
     * @version 1.0
     * @since   2016-07-01
     */
    public enum Algorithm {

        AES_CBC_NONE, AES_CBC_HMACSHA1, AES_CBC_HMACSHA256, AES_GCM_HMACSHA1, AES_GCM_HMACSHA256, HMACSHA1, HMACSHA256
    }

    /**
     * List of key sizes allowed by the policy. Each element defines a key size
     *
     * @author  Raghav S
     * @version 1.0
     * @since   2016-07-01
     */
    public enum KeySize {
        NONE(0), BITS_128(128), BITS_256(256), BITS_512(512);

        private int value;

        KeySize(int value){

            this.value = value;
        }

        public int getKeySize(){

            return value;
        }
    }

    /**
     * Returns the algorithm set in the crypto policy
     * @return returns the Algorithm
     */
    public Algorithm getAlgorithm();

    /**
     * Returns the java cipher transformation string corresponding to the selected algorithm in the policy
     * @return returns the cipher transformation string representing the encryption algorithm, mode and padding
     */
    public String getCipherTranformation();

    /**
     * Returns the encryption algorithm string part of the java cipher transformation string corresponding to the
     * selected algorithm in the policy
     * @return returns the encryption algorithm string
     */
    public String getEncryptionAlgorithmString();

    /**
     * Returns the mac algorithm string part of the java cipher transformation string corresponding to the selected
     * algorithm in the policy
     * @return returns the mac algorithm string
     */
    public String getMacAlgorithmString();

    /**
     * Returns the block size of the symmetric encryption algorithm chosen
     * @return returns the block size in bytes
     */
    public int getBlockSize();

    /**
     * Returns the key size for the encryption algorithm selected in the policy
     * @return returns the encryption key size in bytes
     */
    public int getEncryptKeySize();

    /**
     * Returns the key size for the mac algorithm selected in the policy
     * @return returns the mac key size in bytes
     */
    public int getMacKeySize();

    /**
     * Returns a string that specified the bulk encryption mode. For example: CBC, GCM
     * @return returns the encryption mode string. example: CBC, GCS etc
     */
    public String getMode();

    /**
     * Returns the name of the padding used in the encryption
     * @return return the string representing the padding used. example: PKCS5Padding
     */
    public String getPadding();

    /**
     * Returns the java secure random algorithm specified by the policy
     * @return returns the secure random algorithm string
     */
    public String getSecureRandomAlgo();

    /**
     * Returns the JCE provider specified by the policy
     * @return returns the JCE provide set in the policy
     */
    public String getJCEProvider();

}
