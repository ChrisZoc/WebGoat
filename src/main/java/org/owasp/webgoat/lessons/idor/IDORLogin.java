/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"idor.hints.idor_login"})
public class IDORLogin implements AssignmentEndpoint {
  static final String TOM_USER_ID = "2342384";

  private final LessonSession lessonSession;

  public IDORLogin(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  private static final SecureRandom RANDOM = new SecureRandom();

  /**
   * The accounts used to be hard-coded with trivial, published passwords ("tom"/"cat",
   * "bill"/"buffalo"), so anybody could sign in as tom (CWE-798 / CWE-259). Each account now gets
   * a strong random password when the application starts; it is never written to the lesson
   * content, the logs or any response.
   */
  private final Map<String, IdorAccount> accounts =
      Map.of(
          "tom", new IdorAccount(TOM_USER_ID, randomPassword()),
          "bill", new IdorAccount("2342388", randomPassword()));

  private record IdorAccount(String userId, String password) {}

  private static String randomPassword() {
    byte[] bytes = new byte[24];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  @PostMapping("/IDOR/login")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    IdorAccount account = accounts.get(username);
    if (account != null
        && "tom".equals(username)
        && MessageDigest.isEqual(
            account.password().getBytes(StandardCharsets.UTF_8),
            password.getBytes(StandardCharsets.UTF_8))) {
      lessonSession.setValue("idor-authenticated-as", username);
      lessonSession.setValue("idor-authenticated-user-id", account.userId());
      return success(this).feedback("idor.login.success").feedbackArgs(username).build();
    }
    return failed(this).feedback("idor.login.failure").build();
  }
}
