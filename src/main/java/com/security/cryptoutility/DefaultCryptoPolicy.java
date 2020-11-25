package com.security.cryptoutility;

import com.google.inject.Inject;
import com.google.inject.name.Named;
import org.apache.commons.lang.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Raghav S on 8/24/16.
 */

class DefaultCryptoPolicy implements CryptoPolicy {


        final private String SECURE_RANDOM_ALGO = "NativePRNGBlocking";

        //Block size for AES since that is the only one allowed by the policy
        final private int BLOCK_SIZE = 16;

        final static private Map<Algorithm, String> cipherMap = new HashMap<Algorithm, String>();

        private Algorithm algorithm;

        private KeySize encryptionKeySize;

        private KeySize macKeySize;

        private enum TransformationStringSection{
            CIPHER, MODE, PADDING
        }

        @Inject
        public DefaultCryptoPolicy(Algorithm algorithm,
                                   @Named("EncryptionKeySize") KeySize encryptionKeySize,
                                   @Named("MACKeySize") KeySize macKeySize){

            this.algorithm = algorithm;

            this.encryptionKeySize = encryptionKeySize;

            this.macKeySize = macKeySize;
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


