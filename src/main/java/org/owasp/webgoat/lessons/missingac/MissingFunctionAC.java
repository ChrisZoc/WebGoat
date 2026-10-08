/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.lessons.Category;
import org.owasp.webgoat.container.lessons.Lesson;
import org.springframework.stereotype.Component;

@Component
public class MissingFunctionAC extends Lesson {

  // random per server start: a static, published salt lets anyone compute the user hashes offline
  public static final String PASSWORD_SALT_SIMPLE = randomSalt();
  public static final String PASSWORD_SALT_ADMIN = randomSalt();

  private static String randomSalt() {
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    return Base64.getEncoder().encodeToString(salt);
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
