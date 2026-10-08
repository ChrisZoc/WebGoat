/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Password reset based on a security question.
 *
 * <p>The original answers ("What is your favorite color?") came from a tiny, guessable set and
 * could be brute forced without any limit. The stored answers are now high-entropy secrets that
 * cannot be guessed, the number of wrong answers per account is limited, and a failure no longer
 * tells whether the username exists.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class QuestionsAssignment implements AssignmentEndpoint {

  static final int MAX_FAILED_ATTEMPTS = 3;
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Map<String, String> ANSWERS = new ConcurrentHashMap<>();
  private static final Map<String, AtomicInteger> FAILED_ATTEMPTS = new ConcurrentHashMap<>();

  static {
    Set.of("admin", "jerry", "tom", "larry", "webgoat")
        .forEach(user -> ANSWERS.put(user, randomAnswer()));
  }

  private static String randomAnswer() {
    byte[] bytes = new byte[16];
    RANDOM.nextBytes(bytes);
    return HexFormat.of().formatHex(bytes);
  }

  @PostMapping(
      path = "/PasswordReset/questions",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult passwordReset(
      @RequestParam Map<String, Object> json, @CurrentUsername String webGoatUsername) {
    String securityQuestion = String.valueOf(json.getOrDefault("securityQuestion", ""));
    String username = String.valueOf(json.getOrDefault("username", "")).toLowerCase(Locale.ROOT);

    if ("webgoat".equals(username)) {
      return failed(this).feedback("password-questions-wrong-user").build();
    }

    AtomicInteger failures =
        FAILED_ATTEMPTS.computeIfAbsent(webGoatUsername + "|" + username, k -> new AtomicInteger());
    if (failures.get() >= MAX_FAILED_ATTEMPTS) {
      return failed(this).feedback("password-questions-locked").build();
    }

    String validAnswer = ANSWERS.get(username);
    if (validAnswer != null
        && MessageDigest.isEqual(
            validAnswer.getBytes(StandardCharsets.UTF_8),
            securityQuestion.getBytes(StandardCharsets.UTF_8))) {
      failures.set(0);
      return success(this).build();
    }
    failures.incrementAndGet();
    // same answer for unknown users and for wrong answers: no username enumeration
    return failed(this).feedback("password-questions-incorrect").build();
  }
}
