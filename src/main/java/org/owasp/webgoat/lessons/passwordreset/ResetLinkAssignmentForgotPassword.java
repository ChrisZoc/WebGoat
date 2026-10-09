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
 * configuration (the Host / X-Forwarded-Host headers are never read, so a poisoned request is
 * handled exactly like a normal one), the token is random, hashed, short-lived, single use and bound
 * to the account of the e-mail address, and the answer never completes the assignment.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
@Slf4j
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final ResetTokenStore tokenStore;
  private final String resetPath;
  private final String resetBaseUrl;
  private final String webWolfURL;
  private final String webWolfMailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      ResetTokenStore tokenStore,
      @Value("${webgoat.host}") String webGoatHost,
      @Value("${webgoat.port}") String webGoatPort,
      @Value("${server.servlet.context-path:/WebGoat}") String contextPath,
      @Value("${webwolf.url}") String webWolfURL,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.tokenStore = tokenStore;
    this.resetPath = "/PasswordReset/reset/reset-password/";
    this.resetBaseUrl = "http://" + webGoatHost + ":" + webGoatPort + contextPath + resetPath;
    this.webWolfURL = webWolfURL;
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, @CurrentUsername String username) {
    String account = accountOf(email);
    if (!account.isBlank() && tokenStore.allowRequest(username)) {
      String token = tokenStore.issue(account);
      if (ResetLinkAssignment.TOM_EMAIL.equalsIgnoreCase(email.trim())) {
        simulateTomOpeningHisMail(token);
      } else {
        try {
          sendMailToAccount(account, token);
        } catch (Exception e) {
          log.debug("Password reset e-mail could not be delivered", e);
        }
      }
    }
    // Requesting a link is never an achievement; the answer is the same for every outcome.
    return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
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

  /**
   * Lesson simulation of Tom reading his mail: his mail client opens the link at the configured
   * WebWolf address. The target never comes from the request, so a forged Host header changes
   * nothing, and the token is bound to Tom's account: whoever observes it cannot redeem it from
   * another account, and Tom's password cannot be taken over with it.
   */
  private void simulateTomOpeningHisMail(String token) {
    try {
      restTemplate.getForEntity(webWolfURL + resetPath + token, String.class);
    } catch (Exception e) {
      log.debug("Simulated reset link visit failed", e);
    }
  }
}
