/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;

/**
 * Origin check for state-changing requests, as the OWASP CSRF cheat sheet describes it: the
 * Origin header (or, failing that, the Referer) must name this host. A request carrying
 * neither is refused - for an action that changes state, "no evidence of where it came from"
 * cannot count as "same origin".
 */
final class SameOrigin {

  private SameOrigin() {}

  static boolean check(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null) {
      return false;
    }
    String source = request.getHeader("Origin");
    if (source == null || source.isBlank() || "null".equals(source)) {
      source = request.getHeader("Referer");
    }
    if (source == null || source.isBlank()) {
      return false;
    }
    try {
      URI uri = URI.create(source);
      String authority = uri.getRawAuthority();
      return authority != null && authority.equalsIgnoreCase(host);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }
}
