
package org.apache.tika.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;

public class SemgrepValidation {

    public static byte[] insecureHash(byte[] input)
            throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("MD5").digest(input);
    }

    public static Cipher insecureCipher() throws Exception {
    return Cipher.getInstance("DES");
}
}

