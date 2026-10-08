/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import io.jsonwebtoken.impl.TextCodec;
import java.security.SecureRandom;
import java.util.Base64;

/** Signing keys for the JWT lessons, generated per server start from a CSPRNG. */
public final class JwtSecrets {

  private static final SecureRandom RANDOM = new SecureRandom();

  private JwtSecrets() {}

  /** A base64 encoded 512 bit HMAC key, long enough for HS256 and HS512. */
  public static String randomBase64Key() {
    byte[] key = new byte[64];
    RANDOM.nextBytes(key);
    return TextCodec.BASE64.encode(key);
  }

  /** An unguessable opaque token (e.g. a refresh token). */
  public static String randomToken() {
    byte[] token = new byte[24];
    RANDOM.nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
  }
}
