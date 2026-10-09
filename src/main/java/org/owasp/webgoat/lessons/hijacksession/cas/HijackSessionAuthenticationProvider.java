/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HexFormat;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.ApplicationScope;

/**
 * Issues and checks the lesson's session ids.
 *
 * <p>An id has the form {@code <sequence>-<issued at, epoch millis>-<secret>}. The sequence number
 * and the issue time are kept as non-secret bookkeeping (they are what the lesson shows in the
 * cookie), but they are not what makes an id valid: every id ends in a 128-bit secret drawn from a
 * {@link SecureRandom}, and a session is only found by its complete id. Observing any number of
 * ids therefore says nothing about the secret of a neighbouring one: spotting the gap left by
 * another user's login and walking the timestamps in that gap no longer yields a valid session.
 *
 * @author Angel Olle Blazquez
 */
@ApplicationScope
@Component
public class HijackSessionAuthenticationProvider implements AuthenticationProvider<Authentication> {

  protected static final int MAX_SESSIONS = 50;
  private static final double OTHER_USER_LOGIN_PROBABILITY = 0.25;
  private static final int SECRET_BYTES = 16;

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final HexFormat HEX = HexFormat.of();
  private static final AtomicLong SEQUENCE = new AtomicLong(RANDOM.nextLong() & 0xFFFFFFFFFFFFL);

  private static final Supplier<String> GENERATE_SESSION_ID =
      () -> {
        byte[] secret = new byte[SECRET_BYTES];
        RANDOM.nextBytes(secret);
        return SEQUENCE.incrementAndGet()
            + "-"
            + Instant.now().toEpochMilli()
            + "-"
            + HEX.formatHex(secret);
      };

  public static final Supplier<Authentication> AUTHENTICATION_SUPPLIER =
      () -> Authentication.builder().id(GENERATE_SESSION_ID.get()).build();

  private final Deque<String> sessions = new ArrayDeque<>();

  @Override
  public Authentication authenticate(Authentication authentication) {
    if (authentication == null) {
      return AUTHENTICATION_SUPPLIER.get();
    }

    if (StringUtils.isNotEmpty(authentication.getId()) && isActive(authentication.getId())) {
      authentication.setAuthenticated(true);
      return authentication;
    }

    if (StringUtils.isEmpty(authentication.getId())) {
      authentication.setId(GENERATE_SESSION_ID.get());
    }

    authorizedUserAutoLogin();

    return authentication;
  }

  /** Simulates another user logging in at the same time; their id is just as unguessable. */
  protected void authorizedUserAutoLogin() {
    if (ThreadLocalRandom.current().nextDouble() < OTHER_USER_LOGIN_PROBABILITY) {
      Authentication authentication = AUTHENTICATION_SUPPLIER.get();
      authentication.setAuthenticated(true);
      addSession(authentication.getId());
    }
  }

  protected synchronized boolean addSession(String sessionId) {
    if (sessionId == null) {
      return false;
    }
    while (sessions.size() >= MAX_SESSIONS) {
      sessions.removeFirst();
    }
    return sessions.add(sessionId);
  }

  private synchronized boolean isActive(String sessionId) {
    return sessions.contains(sessionId);
  }

  protected synchronized int getSessionsSize() {
    return sessions.size();
  }
}
