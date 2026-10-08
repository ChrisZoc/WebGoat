/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Locale;

/**
 * Strict same-origin verification for state changing requests (OWASP CSRF cheat sheet, "verifying
 * origin with standard headers"). The source origin is taken from the {@code Origin} header, or
 * from the {@code Referer} header when no Origin is sent, and must match the target host the
 * request was sent to. A request that carries neither header cannot be verified and is treated as
 * cross-site.
 */
final class SameOriginCheck {

  private SameOriginCheck() {}

  static boolean isSameOrigin(HttpServletRequest request) {
    String target = targetAuthority(request);
    if (target == null) {
      return false;
    }
    String origin = request.getHeader("Origin");
    if (origin != null && !origin.isBlank()) {
      return target.equals(authorityOf(origin));
    }
    String referer = request.getHeader("Referer");
    if (referer != null && !referer.isBlank()) {
      return target.equals(authorityOf(referer));
    }
    return false;
  }

  private static String targetAuthority(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null || host.isBlank()) {
      host = request.getServerName() + ":" + request.getServerPort();
    }
    return normalize(host.trim(), request.getScheme());
  }

  private static String authorityOf(String url) {
    try {
      URI uri = URI.create(url.trim());
      if (uri.getRawAuthority() == null || uri.getScheme() == null) {
        return null;
      }
      return normalize(uri.getRawAuthority(), uri.getScheme());
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  /** Lower-cases the authority and adds the default port of the scheme when it is missing. */
  private static String normalize(String authority, String scheme) {
    String value = authority.toLowerCase(Locale.ROOT);
    if (value.contains("@")) {
      return null;
    }
    boolean hasPort = value.startsWith("[") ? value.contains("]:") : value.contains(":");
    if (!hasPort) {
      value = value + ":" + ("https".equalsIgnoreCase(scheme) ? "443" : "80");
    }
    return value;
  }
}
