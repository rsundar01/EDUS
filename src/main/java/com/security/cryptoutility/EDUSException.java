package com.security.cryptoutility;

/**
 * EDUSException describes the exceptions thrown by the EDUS library.
 *
 * @author  Raghav S
 * @version 2.0
 * @since   2016-08-23
 */
public class EDUSException extends Exception {

    public EDUSException(String message) { super(message);}

    public EDUSException(Throwable cause){
        super(cause);
    }

    public EDUSException(String exception, Throwable cause){
        super(exception, cause);
    }

}
