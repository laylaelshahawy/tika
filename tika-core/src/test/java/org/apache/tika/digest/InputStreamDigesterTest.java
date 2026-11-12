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
package org.apache.tika.digest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.metadata.Property;
import org.apache.tika.parser.ParseContext;

public class InputStreamDigesterTest {

    @Test
    public void testReservedDigestKeySurvivesGuard() throws Exception {
        String key = "tk:digest:SHA256";
        InputStreamDigester digester = new InputStreamDigester("SHA256", key,
                bytes -> Base64.getEncoder().encodeToString(bytes));
        Metadata metadata = new Metadata();
        try (TikaInputStream tis =
                     TikaInputStream.get("hello world".getBytes(StandardCharsets.UTF_8))) {
            digester.digest(tis, metadata, new ParseContext());
        }
        assertNotNull(metadata.get(key), "trusted digest write must survive the reserved-key guard");
        assertNotNull(Property.get(key), "digest key must be registered as a Property");
    }

    @Test
    public void testRequestedSha256IsActuallyUsed() throws Exception {
        String key = "tk:digest:SHA256";

        InputStreamDigester digester = new InputStreamDigester(
                "SHA256",
                key,
                bytes -> Base64.getEncoder().encodeToString(bytes));

        Metadata metadata = new Metadata();

        try (TikaInputStream tis =
                    TikaInputStream.get("hello world".getBytes(StandardCharsets.UTF_8))) {
            digester.digest(tis, metadata, new ParseContext());
        }

        String expectedSha256 =
                "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=";

        assertEquals(expectedSha256, metadata.get(key),
                "SHA-256 was requested but a different digest was produced");
    }
}
