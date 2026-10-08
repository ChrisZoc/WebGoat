/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HexFormat;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Email;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * @author nbaars
 * @since 4/8/17.
 */
@RestController
@Slf4j
public class Assignment7 implements AssignmentEndpoint {

  private static final SecureRandom RANDOM = new SecureRandom();

  // Generated per server start from a CSPRNG: the admin reset link must not be static or
  // derivable from the (leaked) link generation code.
  public static final String ADMIN_PASSWORD_LINK = randomToken();

  private static String randomToken() {
    byte[] bytes = new byte[16];
    RANDOM.nextBytes(bytes);
    return HexFormat.of().formatHex(bytes);
  }

  private static final String TEMPLATE =
      "Hi, you requested a password reset link, please use this <a target='_blank'"
          + " href='http://%s/WebGoat/challenge/7/reset-password/%s'>link</a> to reset your"
          + " password.\n"
          + " \n\n"
          + "If you did not request this password change you can ignore this message.\n"
          + "If you have any comments or questions, please do not hesitate to reach us at"
          + " support@webgoat-cloud.org\n\n"
          + "Kind regards, \n"
          + "Team WebGoat";

  private final Flags flags;
  private final RestTemplate restTemplate;
  private final String webWolfMailURL;
  private final String webGoatHost;

  public Assignment7(
      Flags flags,
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.host}") String webGoatHost,
      @Value("${webgoat.port}") String webGoatPort) {
    this.flags = flags;
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
    this.webGoatHost = webGoatHost + ":" + webGoatPort;
  }

  @GetMapping("/challenge/7/reset-password/{link}")
  public ResponseEntity<String> resetPassword(@PathVariable(value = "link") String link) {
    if (MessageDigest.isEqual(
        link.getBytes(StandardCharsets.UTF_8),
        ADMIN_PASSWORD_LINK.getBytes(StandardCharsets.UTF_8))) {
      return ResponseEntity.accepted()
          .body(
              "<h1>Success!!</h1>"
                  + "<img src='/WebGoat/images/hi-five-cat.jpg'>"
                  + "<br/><br/>Here is your flag: "
                  + flags.getFlag(7));
    }
    return ResponseEntity.ok("That is not the reset link for admin");
  }

  @PostMapping("/challenge/7")
  @ResponseBody
  public AttackResult sendPasswordResetLink(@RequestParam String email) {
    int at = StringUtils.hasText(email) ? email.indexOf('@') : -1;
    String username = at > 0 ? email.substring(0, at) : null;
    if (StringUtils.hasText(username)) {
      Email mail =
          Email.builder()
              .title("Your password reset link for challenge 7")
              .contents(
                  // host from configuration (not the Host header); token from a CSPRNG, never
                  // derived from the username
                  String.format(TEMPLATE, webGoatHost, randomToken()))
              .sender("password-reset@webgoat-cloud.net")
              .recipient(username)
              .time(LocalDateTime.now())
              .build();
      restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
    }
    // Sending a reset link is not solving the challenge: never report lessonCompleted here.
    return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
  }

  /** The repository (and with it the reset link generation code) is no longer published. */
  @GetMapping(value = "/challenge/7/.git", produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public ResponseEntity<String> git() {
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .contentType(MediaType.TEXT_PLAIN)
        .body("Access to the source repository is forbidden.");
  }
}
