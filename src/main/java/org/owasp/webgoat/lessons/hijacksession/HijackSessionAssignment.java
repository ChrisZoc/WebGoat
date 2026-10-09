/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.hijacksession.cas.Authentication;
import org.owasp.webgoat.lessons.hijacksession.cas.HijackSessionAuthenticationProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

@RestController
@AssignmentHints({
  "hijacksession.hints.1",
  "hijacksession.hints.2",
  "hijacksession.hints.3",
  "hijacksession.hints.4",
  "hijacksession.hints.5"
})
public class HijackSessionAssignment implements AssignmentEndpoint {
  private static final String COOKIE_NAME = "hijack_cookie";
  private static final Duration COOKIE_MAX_AGE = Duration.ofMinutes(15);

  private final HijackSessionAuthenticationProvider provider;

  public HijackSessionAssignment(HijackSessionAuthenticationProvider provider) {
    this.provider = provider;
  }

  @PostMapping(path = "/HijackSession/login")
  @ResponseBody
  public AttackResult login(
      @RequestParam(required = false) String username,
      @RequestParam(required = false) String password,
      @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
      @CurrentUsername String webGoatUser,
      HttpServletRequest request,
      HttpServletResponse response) {

    if (StringUtils.isNotEmpty(cookieValue)) {
      // A session id is only honoured when this server issued it to this very WebGoat user for this
      // very account name. Ids issued to anybody else, guessed or forged ids, and ids presented
      // without the account they belong to are never accepted.
      Authentication resumed = provider.resume(webGoatUser, username, cookieValue);
      if (resumed.isAuthenticated()) {
        // using one's own session is not a hijack: it never completes the assignment
        return informationMessage(this).feedback("hijacksession.own-session").build();
      }
      // the unknown id is dropped on the client; it is not removed server side, so presenting
      // somebody else's id cannot be used to terminate their session either
      clearCookie(request, response);
    }

    if (StringUtils.isAnyBlank(username, password)) {
      return failed(this).feedback("hijacksession.credentials-required").build();
    }

    // every login gets a brand-new random id (session regeneration on authentication)
    Authentication authentication = provider.login(webGoatUser, username, password);
    if (authentication.getId() != null) {
      setCookie(request, response, authentication.getId());
    }
    return failed(this).build();
  }

  private static String cookiePath(HttpServletRequest request) {
    return request.getContextPath() + "/HijackSession";
  }

  private void setCookie(HttpServletRequest request, HttpServletResponse response, String value) {
    ResponseCookie cookie =
        ResponseCookie.from(COOKIE_NAME, value)
            .path(cookiePath(request))
            .httpOnly(true)
            .secure(true)
            .sameSite("Strict")
            .maxAge(COOKIE_MAX_AGE)
            .build();
    response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
  }

  private void clearCookie(HttpServletRequest request, HttpServletResponse response) {
    ResponseCookie cookie =
        ResponseCookie.from(COOKIE_NAME, "")
            .path(cookiePath(request))
            .httpOnly(true)
            .secure(true)
            .sameSite("Strict")
            .maxAge(0)
            .build();
    response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
  }
}
