/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import org.owasp.webgoat.container.lessons.Category;
import org.owasp.webgoat.container.lessons.Lesson;
import org.springframework.stereotype.Component;

@Component
public class MissingFunctionAC extends Lesson {

  // The salts used to be literals in this file, and so in every public copy of it. A salt
  // that is identical for every install and printed in the source adds nothing: anyone who
  // knows a password can compute the hash offline. They are now generated at startup and
  // never leave the server.
  public static final String PASSWORD_SALT_SIMPLE = randomSalt();
  public static final String PASSWORD_SALT_ADMIN = randomSalt();

  private static String randomSalt() {
    byte[] bytes = new byte[24];
    new java.security.SecureRandom().nextBytes(bytes);
    return java.util.Base64.getEncoder().encodeToString(bytes);
  }

  @Override
  public Category getDefaultCategory() {
    return Category.A1;
  }

  @Override
  public String getTitle() {
    return "missing-function-access-control.title";
  }
}
