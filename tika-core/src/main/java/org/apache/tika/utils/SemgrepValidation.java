/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tika.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.SAXException;

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

    public static SAXParser insecureXmlParser()
        throws ParserConfigurationException, SAXException {

    SAXParserFactory factory = SAXParserFactory.newInstance();
    return factory.newSAXParser();
    }

}
