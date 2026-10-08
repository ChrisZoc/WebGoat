/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Per-user secret code for the WebWolf introduction. It used to be the reversed username, which
 * anybody can compute without ever receiving the e-mail or the landing page request. The code is
 * now random (CSPRNG) and only delivered through WebWolf (mailbox / landing page).
 */
@Component
public class UniqueCodes {

  private static final char[] ALPHABET =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
  private static final int MIN_LENGTH = 6;
  private final SecureRandom random = new SecureRandom();
  private final Map<String, String> codes = new ConcurrentHashMap<>();

  public String codeFor(String username) {
    return codes.computeIfAbsent(username, this::newCode);
  }

  public boolean matches(String username, String candidate) {
    if (username == null || candidate == null) {
      return false;
    }
    String expected = codes.get(username);
    return expected != null
        && MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8), candidate.getBytes(StandardCharsets.UTF_8));
  }

  private String newCode(String username) {
    // as long as the username (the length of the old code, so clients that cut the code out of
    // the e-mail by that length keep working), but never shorter than MIN_LENGTH characters;
    // 62^6 > 5*10^10 possibilities cannot be guessed online
    int length = Math.max(MIN_LENGTH, username.length());
    StringBuilder sb = new StringBuilder(length);
    for (int i = 0; i < length; i++) {
      sb.append(ALPHABET[random.nextInt(ALPHABET.length)]);
    }
    return sb.toString();
  }
}
