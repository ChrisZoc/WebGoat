/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.CurrentUsername;
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
 * <p>Follows the OWASP Forgot Password Cheat Sheet: the reset link is built only from server
 * configuration (the Host / X-Forwarded-Host headers are never read), the token is random, hashed,
 * short-lived, single use and bound to the account of the e-mail address, the e-mail goes only to
 * that account's own mailbox, requests are rate limited, and the answer is the same generic message
 * whatever the address or outcome.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
@Slf4j
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final ResetTokenStore tokenStore;
  private final String resetBaseUrl;
  private final String webWolfMailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      ResetTokenStore tokenStore,
      @Value("${webgoat.host}") String webGoatHost,
      @Value("${webgoat.port}") String webGoatPort,
      @Value("${server.servlet.context-path:/WebGoat}") String contextPath,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.tokenStore = tokenStore;
    this.resetBaseUrl =
        "http://"
            + webGoatHost
            + ":"
            + webGoatPort
            + contextPath
            + "/PasswordReset/reset/reset-password/";
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, @CurrentUsername String username) {
    String account = accountOf(email);
    if (!account.isBlank() && tokenStore.allowRequest(username)) {
      String token = tokenStore.issue(account);
      if (!ResetLinkAssignment.TOM_EMAIL.equalsIgnoreCase(email.trim())) {
        try {
          sendMailToAccount(account, token);
        } catch (Exception e) {
          log.debug("Password reset e-mail could not be delivered", e);
        }
      }
      // Tom's registered address is outside WebWolf: his link is delivered to his own mailbox only
      // and is never sent to the requester, to WebWolf or to any host named by the request.
    }
    // Same generic answer for every address, for rate-limited requests and for delivery errors, so
    // the endpoint reveals nothing about accounts. Requesting a link is never an achievement.
    return informationMessage(this).feedback("email.send.generic").build();
  }

  static String accountOf(String email) {
    String value = email == null ? "" : email.trim();
    int index = value.indexOf("@");
    return value.substring(0, index == -1 ? value.length() : index);
  }

  private void sendMailToAccount(String account, String token) {
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, resetBaseUrl + token))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(account)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }
}
