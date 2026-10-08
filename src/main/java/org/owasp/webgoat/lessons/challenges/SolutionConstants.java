/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

import java.security.SecureRandom;
import java.util.Base64;

public final class SolutionConstants {

  // Random per server start, so the admin password is neither hardcoded nor derivable from
  // anything the application serves.
  public static final String PASSWORD = randomPassword();

  private SolutionConstants() {}

  private static String randomPassword() {
    byte[] bytes = new byte[24];
    new SecureRandom().nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
