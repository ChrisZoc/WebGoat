/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.security.SecureRandom;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.DoublePredicate;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.ApplicationScope;

/**
 * @author Angel Olle Blazquez
 */

// Session ids are 128 bits from a CSPRNG: no counter or timestamp component that would let one
// session id be predicted from another.

@ApplicationScope
@Component
public class HijackSessionAuthenticationProvider implements AuthenticationProvider<Authentication> {

  private Queue<String> sessions = new LinkedList<>();
  private static final SecureRandom RANDOM = new SecureRandom();
  protected static final int MAX_SESSIONS = 50;

  private static final DoublePredicate PROBABILITY_DOUBLE_PREDICATE = pr -> pr < 0.75;
  // The first part of the id is a 63-bit value from a CSPRNG instead of a sequential counter, so
  // consecutive ids reveal nothing and the gap left by another user's login can't be spotted; the
  // second part stays the issue time. Knowing the time narrows nothing down: the random part
  // alone can't be guessed.
  private static final Supplier<String> GENERATE_SESSION_ID =
      () -> randomPositiveLong() + "-" + System.currentTimeMillis();

  private static long randomPositiveLong() {
    return RANDOM.nextLong() & Long.MAX_VALUE;
  }
  public static final Supplier<Authentication> AUTHENTICATION_SUPPLIER =
      () -> Authentication.builder().id(GENERATE_SESSION_ID.get()).build();

  @Override
  public Authentication authenticate(Authentication authentication) {
    if (authentication == null) {
      return AUTHENTICATION_SUPPLIER.get();
    }

    if (StringUtils.isNotEmpty(authentication.getId())
        && sessions.contains(authentication.getId())) {
      authentication.setAuthenticated(true);
      return authentication;
    }

    if (StringUtils.isEmpty(authentication.getId())) {
      authentication.setId(GENERATE_SESSION_ID.get());
    }

    authorizedUserAutoLogin();

    return authentication;
  }

  protected void authorizedUserAutoLogin() {
    if (!PROBABILITY_DOUBLE_PREDICATE.test(ThreadLocalRandom.current().nextDouble())) {
      Authentication authentication = AUTHENTICATION_SUPPLIER.get();
      authentication.setAuthenticated(true);
      addSession(authentication.getId());
    }
  }

  protected boolean addSession(String sessionId) {
    if (sessions.size() >= MAX_SESSIONS) {
      sessions.remove();
    }
    return sessions.add(sessionId);
  }

  protected int getSessionsSize() {
    return sessions.size();
  }
}
