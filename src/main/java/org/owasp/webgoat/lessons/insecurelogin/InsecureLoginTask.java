/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
public class InsecureLoginTask implements AssignmentEndpoint {

  private static final String USERNAME = "CaptainJack";

  /**
   * The password used to be hard-coded ("BlackPearl") and shipped to every browser inside
   * credentials.js, which then sent it in plaintext with every click. The credential now only
   * exists on the server: it is generated randomly at start-up and never sent to the client.
   */
  private final String secretPassword = randomPassword();

  private static String randomPassword() {
    byte[] bytes = new byte[24];
    new SecureRandom().nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  @PostMapping("/InsecureLogin/task")
  @ResponseBody
  public AttackResult completed(
      @RequestParam(required = false) String username,
      @RequestParam(required = false) String password) {
    if (USERNAME.equals(username)
        && password != null
        && MessageDigest.isEqual(
            secretPassword.getBytes(StandardCharsets.UTF_8),
            password.getBytes(StandardCharsets.UTF_8))) {
      return success(this).feedback("insecure-login.intercept.success").build();
    }
    return failed(this).feedback("insecure-login.intercept.failure").build();
  }

  @PostMapping("/InsecureLogin/login")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public void login() {
    // only need to exists as the JS needs to call an existing endpoint
  }
}
