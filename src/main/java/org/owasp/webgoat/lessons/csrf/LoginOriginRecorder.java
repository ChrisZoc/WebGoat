/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Records, on the session created by a form login, whether that login request was verifiably
 * same-origin (Origin / Referer header matching the target host). A login forged from another site
 * (login CSRF) therefore yields a session that is flagged as not trusted, and {@link CSRFLogin}
 * refuses it.
 *
 * <p>Runs before the Spring Security filter chain (order -100) so that it wraps the login
 * processing. It never blocks or alters the login itself.
 */
@Component
@Order(-101)
public class LoginOriginRecorder extends OncePerRequestFilter {

  static final String LOGIN_ORIGIN_VERIFIED = "webgoat.csrf.login-origin-verified";

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !"POST".equalsIgnoreCase(request.getMethod())
        || !"/login".equals(request.getServletPath());
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    boolean sameOrigin = SameOriginCheck.isSameOrigin(request);
    try {
      filterChain.doFilter(request, response);
    } finally {
      HttpSession session = request.getSession(false);
      if (session != null) {
        try {
          session.setAttribute(LOGIN_ORIGIN_VERIFIED, sameOrigin);
        } catch (IllegalStateException e) {
          // session was invalidated during processing, nothing to record
        }
      }
    }
  }

  static boolean loginOriginVerified(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    return session != null
        && Boolean.TRUE.equals(session.getAttribute(LOGIN_ORIGIN_VERIFIED));
  }
}
