/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * One random code per user, delivered through WebWolf (by mail, or on the landing page) and
 * checked here. It used to be the user name reversed: a "secret" anyone can compute from
 * something they already know proves nothing about having received the message.
 */
final class UniqueCodes {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Map<String, String> CODES = new ConcurrentHashMap<>();

  private UniqueCodes() {}

  static String codeFor(String username) {
    return CODES.computeIfAbsent(
        username,
        u -> {
          byte[] bytes = new byte[12];
          RANDOM.nextBytes(bytes);
          return HexFormat.of().formatHex(bytes);
        });
  }

  static boolean matches(String username, String submitted) {
    return submitted != null
        && java.security.MessageDigest.isEqual(
            codeFor(username).getBytes(java.nio.charset.StandardCharsets.UTF_8),
            submitted.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }
}
