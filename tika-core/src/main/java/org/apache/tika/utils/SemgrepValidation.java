
package org.apache.tika.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class SemgrepValidation {

    public static byte[] insecureHash(byte[] input)
            throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("MD5").digest(input);
    }

    public static Cipher insecureCipher() throws Exception {
    return Cipher.getInstance("DES");
    }

    public static ResultSet insecureQuery(Connection connection, String username)
        throws SQLException {
    Statement statement = connection.createStatement();
    return statement.executeQuery(
            "SELECT * FROM users WHERE username = '" + username + "'");
    }
}

