package com.security.cryptoutility;

import com.google.inject.Inject;
import org.apache.commons.lang.StringUtils;

/**
 * Created by cloudera on 11/11/16.
 */
public class MockCryptoPolicy implements CryptoPolicy {

    final private String SECURE_RANDOM_ALGO = "NativePRNG";

    //Block size for AES since that is the only one allowed by the policy
    final private int BLOCK_SIZE = 16;

    private KeySize encryptionKeySize = KeySize.BITS_128;

    private KeySize macKeySize = KeySize.BITS_256;

    private Algorithm algorithm = Algorithm.AES_CBC_HMACSHA256;

    private enum TransformationStringSection{
        CIPHER, MODE, PADDING
    }

    @Inject
    public MockCryptoPolicy(){

    }

    public Algorithm getAlgorithm(){

        return algorithm;

    }

    public String getCipherTranformation(){

        switch(algorithm){
            case AES_CBC_NONE:
                return "AES/CBC/PKCS5Padding";

            case AES_CBC_HMACSHA1:
            case AES_CBC_HMACSHA256:
                return "AES/CBC/PKCS5Padding";

            case AES_GCM_HMACSHA1:
            case AES_GCM_HMACSHA256:
                return "AES/GCM/NoPadding";

            default:
                return "";

        }

    }

    public String getEncryptionAlgorithmString(){

        return parseTransformationString(TransformationStringSection.CIPHER);
    }

    public int getBlockSize() { return BLOCK_SIZE; }

    public int getEncryptKeySize() {

        return encryptionKeySize.getKeySize()/8;
    }

    public int getMacKeySize() {

        return macKeySize.getKeySize() / 8;
    }

    public String getMacAlgorithmString() {

        switch(algorithm){

            case HMACSHA1:
            case AES_CBC_HMACSHA1:
            case AES_GCM_HMACSHA1:
                return "HmacSHA1";

            case HMACSHA256:
            case AES_CBC_HMACSHA256:
            case AES_GCM_HMACSHA256:
                return "HmacSHA256";

            default:
                return "";

        }
    }

    public String getMode(){

        return parseTransformationString(TransformationStringSection.MODE);
    }

    public String getPadding(){

        return parseTransformationString(TransformationStringSection.PADDING);
    }

    private String parseTransformationString(TransformationStringSection transformationStringSection){

        String algorithmString = getCipherTranformation();

        if( !algorithmString.isEmpty() &&
                StringUtils.countMatches(algorithmString, "/") >= transformationStringSection.ordinal() ) {

            return algorithmString.split("/")[transformationStringSection.ordinal()];

        } else {

            return algorithmString;
        }
    }

    public String getSecureRandomAlgo(){
        return SECURE_RANDOM_ALGO;
    }

    public String getJCEProvider(){
        return "SunJCE";
    }

}
