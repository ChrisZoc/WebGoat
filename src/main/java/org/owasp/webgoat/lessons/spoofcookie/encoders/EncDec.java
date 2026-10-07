/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.security.crypto.codec.Hex;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

public class EncDec {

  private static final byte[] KEY = newKey();

  private static byte[] newKey() {
    byte[] key = new byte[32];
    new java.security.SecureRandom().nextBytes(key);
    return key;
  }

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    // An encoding is not a signature: base64(hex(reverse(user + salt))) can be decoded,
    // edited and re-encoded by anyone, salt included. The cookie now carries the user name
    // plus an HMAC under a key that never leaves the server, so it cannot be forged.
    String user = value.toLowerCase();
    return Base64.getEncoder()
        .encodeToString((user + ":" + mac(user)).getBytes(StandardCharsets.UTF_8));
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    String decoded = new String(Base64.getDecoder().decode(encodedValue), StandardCharsets.UTF_8);
    int separator = decoded.lastIndexOf(':');
    if (separator <= 0) {
      throw new IllegalArgumentException("Invalid cookie");
    }
    String user = decoded.substring(0, separator);
    byte[] expected = mac(user).getBytes(StandardCharsets.UTF_8);
    byte[] actual = decoded.substring(separator + 1).getBytes(StandardCharsets.UTF_8);
    if (!java.security.MessageDigest.isEqual(expected, actual)) {
      throw new IllegalArgumentException("Invalid cookie");
    }
    return user;
  }

  private static String mac(final String value) {
    try {
      javax.crypto.Mac hmac = javax.crypto.Mac.getInstance("HmacSHA256");
      hmac.init(new javax.crypto.spec.SecretKeySpec(KEY, "HmacSHA256"));
      return new String(Hex.encode(hmac.doFinal(value.getBytes(StandardCharsets.UTF_8))));
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

}
