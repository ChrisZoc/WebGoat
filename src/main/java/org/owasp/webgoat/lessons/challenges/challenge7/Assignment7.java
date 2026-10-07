/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Email;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
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

  // Issued reset links and the user each one resets. Random and single-use: the admin link
  // used to be the constant 375afe11... in this file, produced by a generator that seeded
  // admin's Random with a fixed value - and that generator's source was served below as /.git
  private static final java.util.Map<String, String> ISSUED_LINKS =
      new java.util.concurrent.ConcurrentHashMap<>();
  private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

  private static String newLink(String username) {
    byte[] bytes = new byte[16];
    RANDOM.nextBytes(bytes);
    String link = java.util.HexFormat.of().formatHex(bytes);
    ISSUED_LINKS.put(link, username);
    return link;
  }

  private static final String TEMPLATE =
      "Hi, you requested a password reset link, please use this <a target='_blank'"
          + " href='%s:8080/WebGoat/challenge/7/reset-password/%s'>link</a> to reset your"
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

  public Assignment7(
      Flags flags, RestTemplate restTemplate, @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.flags = flags;
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
  }

  @GetMapping("/challenge/7/reset-password/{link}")
  public ResponseEntity<String> resetPassword(@PathVariable(value = "link") String link) {
    if ("admin".equalsIgnoreCase(ISSUED_LINKS.remove(link))) {
      return ResponseEntity.accepted()
          .body(
              "<h1>Success!!</h1>"
                  + "<img src='/WebGoat/images/hi-five-cat.jpg'>"
                  + "<br/><br/>Here is your flag: "
                  + flags.getFlag(7));
    }
    return ResponseEntity.status(HttpStatus.I_AM_A_TEAPOT)
        .body("That is not the reset link for admin");
  }

  @PostMapping("/challenge/7")
  @ResponseBody
  public AttackResult sendPasswordResetLink(@RequestParam String email, HttpServletRequest request)
      throws URISyntaxException {
    if (StringUtils.hasText(email)) {
      String username = email.substring(0, email.indexOf("@"));
      if (StringUtils.hasText(username)) {
        URI uri = new URI(request.getRequestURL().toString());
        Email mail =
            Email.builder()
                .title("Your password reset link for challenge 7")
                .contents(
                    String.format(
                        TEMPLATE,
                        uri.getScheme() + "://" + uri.getHost(),
                        newLink(username)))
                .sender("password-reset@webgoat-cloud.net")
                .recipient(username)
                .time(LocalDateTime.now())
                .build();
        restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
      }
    }
    // Sending a mail is an acknowledgement, not the completion of anything
    return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
  }
}
