/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.ApplicationScope;

/**
 * Session management following the OWASP Session Management Cheat Sheet / ASVS V3:
 *
 * <ul>
 *   <li>session ids are 256 bits from a CSPRNG, base64url encoded: opaque, no counter, timestamp or
 *       any other structure that would let one id be derived from another
 *   <li>ids are only accepted when the server issued them; they are stored server side together
 *       with the principal (the WebGoat user and the account name) they were issued to, and are
 *       only valid for that same principal
 *   <li>a new id is issued on every login, ids expire after an idle and an absolute timeout
 * </ul>
 *
 * @author Angel Olle Blazquez
 */
@ApplicationScope
@Component
public class HijackSessionAuthenticationProvider {

  static final Duration IDLE_TIMEOUT = Duration.ofMinutes(15);
  static final Duration ABSOLUTE_TIMEOUT = Duration.ofHours(2);
  static final int MAX_SESSIONS = 10_000;

  private static final SecureRandom RANDOM = new SecureRandom();

  private static final class Session {
    private final String owner;
    private final String name;
    private final Instant created;
    private volatile Instant lastUsed;

    private Session(String owner, String name, Instant now) {
      this.owner = owner;
      this.name = name;
      this.created = now;
      this.lastUsed = now;
    }
  }

  private final Map<String, Session> sessions = new ConcurrentHashMap<>();
  private final Clock clock;

  public HijackSessionAuthenticationProvider() {
    this(Clock.systemUTC());
  }

  HijackSessionAuthenticationProvider(Clock clock) {
    this.clock = clock;
  }

  /**
   * Starts a new session for {@code username}, logged in by WebGoat user {@code owner}. The
   * returned authentication carries a fresh random id; any previously presented id is discarded by
   * the caller (see {@link #invalidate(String)}). The lesson has no account store, so the
   * credentials themselves are never considered verified.
   */
  public Authentication login(String owner, String username, String password) {
    if (StringUtils.isAnyBlank(owner, username, password)) {
      return Authentication.builder().name(username).build();
    }
    purgeExpired();
    if (sessions.size() >= MAX_SESSIONS) {
      // never evict somebody else's session to make room; just refuse to create more
      return Authentication.builder().name(username).build();
    }
    String id = newId();
    sessions.put(id, new Session(owner, username, clock.instant()));
    return Authentication.builder().name(username).credentials(null).id(id).build();
  }

  /**
   * Resumes a session: authenticated only if {@code id} was issued by this server, has not expired
   * and belongs to exactly this WebGoat user and this account name.
   */
  public Authentication resume(String owner, String username, String id) {
    Authentication authentication = Authentication.builder().name(username).id(id).build();
    if (StringUtils.isAnyBlank(owner, username, id)) {
      return authentication;
    }
    Session session = sessions.get(id);
    if (session == null) {
      return authentication;
    }
    Instant now = clock.instant();
    if (isExpired(session, now)) {
      sessions.remove(id, session);
      return authentication;
    }
    if (equal(session.owner, owner) && equal(session.name, username)) {
      session.lastUsed = now;
      authentication.setAuthenticated(true);
    }
    return authentication;
  }

  public void invalidate(String id) {
    if (StringUtils.isNotEmpty(id)) {
      sessions.remove(id);
    }
  }

  int getSessionsSize() {
    return sessions.size();
  }

  private boolean isExpired(Session session, Instant now) {
    return !now.isBefore(session.lastUsed.plus(IDLE_TIMEOUT))
        || !now.isBefore(session.created.plus(ABSOLUTE_TIMEOUT));
  }

  private void purgeExpired() {
    Instant now = clock.instant();
    sessions.values().removeIf(s -> isExpired(s, now));
  }

  private static boolean equal(String a, String b) {
    return MessageDigest.isEqual(
        a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
  }

  private static String newId() {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }
}
