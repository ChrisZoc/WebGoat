/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.spoofcookie.encoders.EncDec;
import org.springframework.web.bind.UnsatisfiedServletRequestParameterException;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

@AssignmentHints({"spoofcookie.hint1", "spoofcookie.hint2", "spoofcookie.hint3"})
@RestController
public class SpoofCookieAssignment implements AssignmentEndpoint {

  private static final String COOKIE_NAME = "spoof_auth";
  private static final String COOKIE_INFO =
      "Cookie details for user %s:<br />" + COOKIE_NAME + "=%s";
  private static final String ATTACK_USERNAME = "tom";

  // Server-side key used to sign the cookie. The encoding in EncDec is reversible, so without a
  // signature anyone could craft a cookie for any user.
  private static final byte[] COOKIE_SIGNING_KEY = newSigningKey();

  private static final Map<String, String> users =
      Map.of("webgoat", "webgoat", "admin", "admin", ATTACK_USERNAME, "apasswordfortom");

  @PostMapping(path = "/SpoofCookie/login")
  @ResponseBody
  @ExceptionHandler(UnsatisfiedServletRequestParameterException.class)
  public AttackResult login(
      @RequestParam String username,
      @RequestParam String password,
      @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
      HttpServletResponse response) {

    if (StringUtils.isEmpty(cookieValue)) {
      return credentialsLoginFlow(username, password, response);
    } else {
      return cookieLoginFlow(cookieValue);
    }
  }

  @GetMapping(path = "/SpoofCookie/cleanup")
  public void cleanup(HttpServletResponse response) {
    Cookie cookie = new Cookie(COOKIE_NAME, "");
    cookie.setMaxAge(0);
    response.addCookie(cookie);
  }

  private AttackResult credentialsLoginFlow(
      String username, String password, HttpServletResponse response) {
    String lowerCasedUsername = username.toLowerCase();
    if (ATTACK_USERNAME.equals(lowerCasedUsername)
        && users.get(lowerCasedUsername).equals(password)) {
      return informationMessage(this).feedback("spoofcookie.cheating").build();
    }

    String authPassword = users.getOrDefault(lowerCasedUsername, "");
    if (!authPassword.isBlank() && authPassword.equals(password)) {
      String newCookieValue = sign(EncDec.encode(lowerCasedUsername));
      Cookie newCookie = new Cookie(COOKIE_NAME, newCookieValue);
      newCookie.setPath("/WebGoat");
      newCookie.setSecure(true);
      response.addCookie(newCookie);
      return informationMessage(this)
          .feedback("spoofcookie.login")
          .output(String.format(COOKIE_INFO, lowerCasedUsername, newCookie.getValue()))
          .build();
    }

    return informationMessage(this).feedback("spoofcookie.wrong-login").build();
  }

  private AttackResult cookieLoginFlow(String cookieValue) {
    String encodedUsername = verify(cookieValue);
    if (encodedUsername == null) {
      return failed(this).feedback("spoofcookie.wrong-cookie").build();
    }
    String cookieUsername;
    try {
      cookieUsername = EncDec.decode(encodedUsername).toLowerCase();
    } catch (Exception e) {
      // for providing some instructive guidance, we won't return 4xx error here
      return failed(this).output(e.getMessage()).build();
    }
    if (users.containsKey(cookieUsername)) {
      if (cookieUsername.equals(ATTACK_USERNAME)) {
        return success(this).build();
      }
      return failed(this)
          .feedback("spoofcookie.cookie-login")
          .output(String.format(COOKIE_INFO, cookieUsername, cookieValue))
          .build();
    }

    return failed(this).feedback("spoofcookie.wrong-cookie").build();
  }

  private static byte[] newSigningKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }

  private static String hmac(String value) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(COOKIE_SIGNING_KEY, "HmacSHA256"));
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HmacSHA256 not available", e);
    }
  }

  private static String sign(String encodedValue) {
    return encodedValue + "." + hmac(encodedValue);
  }

  /** Returns the signed payload if the signature is valid, otherwise {@code null}. */
  private static String verify(String cookieValue) {
    int separator = cookieValue.lastIndexOf('.');
    if (separator <= 0) {
      return null;
    }
    String payload = cookieValue.substring(0, separator);
    byte[] expected = hmac(payload).getBytes(StandardCharsets.UTF_8);
    byte[] actual = cookieValue.substring(separator + 1).getBytes(StandardCharsets.UTF_8);
    return MessageDigest.isEqual(expected, actual) ? payload : null;
  }
}
