/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
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
  private final String webGoatPort;
  private final String webWolfHostAndPort;
  private final String webWolfMailURL;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webgoat.host}") String webGoatHost,
      @Value("${webgoat.port}") String webGoatPort,
      @Value("${webwolf.host}") String webWolfHost,
      @Value("${webwolf.port}") String webWolfPort,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.webGoatHost = webGoatHost + ":" + webGoatPort;
    this.webGoatPort = webGoatPort;
    this.webWolfHostAndPort = webWolfHost + ":" + webWolfPort;
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, HttpServletRequest request) {
    // A request whose Host header names another server (e.g. WebWolf) than the one it actually
    // reached is a Host header poisoning attempt: no reset link is created or sent for it at all,
    // so there is no token that could end up on the attacker's server.
    if (isForgedHost(request)) {
      return failed(this).feedback("password-reset-host-rejected").build();
    }
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

  private boolean isForgedHost(HttpServletRequest request) {
    String host = request.getHeader(HttpHeaders.HOST);
    if (host == null || host.isBlank()) {
      return false;
    }
    host = host.trim();
    if (host.equalsIgnoreCase(webWolfHostAndPort)) {
      return true;
    }
    int colon = host.lastIndexOf(':');
    String port;
    if (colon > host.lastIndexOf(']')) {
      port = host.substring(colon + 1);
    } else {
      port = request.isSecure() ? "443" : "80";
    }
    // the port in the Host header must be the port this request really arrived on (or the
    // configured WebGoat port, for deployments behind a port mapping)
    return !port.equals(String.valueOf(request.getLocalPort())) && !port.equals(webGoatPort);
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
