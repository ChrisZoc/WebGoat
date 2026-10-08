/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import java.util.UUID;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final String webGoatHost;
  private final String webWolfMailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webgoat.host}") String webGoatHost,
      @Value("${webgoat.port}") String webGoatPort,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.webGoatHost = webGoatHost + ":" + webGoatPort;
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email) {
    String resetLink = UUID.randomUUID().toString();
    // The link belongs to the account of the e-mail address it is sent to, not to whoever asked
    // for it: only that account can redeem it (see ResetLinkAssignment#changePassword).
    ResetLinkAssignment.resetLinks.put(resetLink, accountOf(email));
    // The host in the reset link comes from server configuration, never from the request's Host
    // header: a forged Host header must not be able to send the reset token to another server.
    if (!ResetLinkAssignment.TOM_EMAIL.equals(email)) {
      // Tom's link is delivered to Tom's own mailbox only, never to WebWolf or the requester.
      try {
        sendMailToUser(email, resetLink);
      } catch (Exception e) {
        return failed(this).output("E-mail can't be send. please try again.").build();
      }
    }

    // Requesting a reset link is not an achievement: whatever Host header or e-mail address the
    // client sends, this endpoint only reports that the e-mail was sent and never marks the
    // assignment as solved.
    return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
  }

  private static String accountOf(String email) {
    int index = email.indexOf("@");
    return email.substring(0, index == -1 ? email.length() : index);
  }

  private void sendMailToUser(String email, String resetLink) {
    String username = accountOf(email);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, webGoatHost, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }
}
