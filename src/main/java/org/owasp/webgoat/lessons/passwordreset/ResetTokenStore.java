/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Password reset tokens following the OWASP Forgot Password Cheat Sheet:
 *
 * <ul>
 *   <li>122 random bits from a CSPRNG, in the lesson's link format (a random UUID)
 *   <li>only a SHA-256 hash of the token is stored, bound to the account it was issued for
 *   <li>short lifetime, single use, and every older token of the account is invalidated when a new
 *       one is issued or one is redeemed
 *   <li>reset requests are rate limited per requester
 * </ul>
 */
@Component
public class ResetTokenStore {

  static final Duration TOKEN_LIFETIME = Duration.ofMinutes(15);
  static final Duration RATE_WINDOW = Duration.ofMinutes(15);
  static final int MAX_REQUESTS_PER_WINDOW = 30;

  private record Entry(String account, Instant expiresAt) {}

  // SHA-256(token) -> account + expiry
  private final Map<String, Entry> tokens = new ConcurrentHashMap<>();
  // requester -> timestamps of recent reset requests
  private final Map<String, Deque<Instant>> requests = new ConcurrentHashMap<>();
  private final Clock clock;

  public ResetTokenStore() {
    this(Clock.systemUTC());
  }

  ResetTokenStore(Clock clock) {
    this.clock = clock;
  }

  /** Issues a new token for {@code account}; earlier tokens of that account stop working. */
  public String issue(String account) {
    // UUID.randomUUID() draws from SecureRandom; the link keeps the format the lesson has always
    // used, while what makes it safe is that it is bound to the account, short-lived and single use.
    String token = UUID.randomUUID().toString();
    tokens.values().removeIf(e -> e.account().equals(account));
    tokens.put(hash(token), new Entry(account, clock.instant().plus(TOKEN_LIFETIME)));
    purgeExpired();
    return token;
  }

  /** True when the token was issued, has not expired and has not been used yet. */
  public boolean isValid(String token) {
    if (token == null || token.isEmpty()) {
      return false;
    }
    Entry entry = tokens.get(hash(token));
    return entry != null && clock.instant().isBefore(entry.expiresAt());
  }

  /**
   * Redeems the token for {@code account}: succeeds only when the token is valid and was issued for
   * exactly that account. A successful redemption removes the token (single use).
   */
  public boolean consume(String token, String account) {
    if (token == null || token.isEmpty() || account == null) {
      return false;
    }
    String key = hash(token);
    Entry entry = tokens.get(key);
    if (entry == null
        || !clock.instant().isBefore(entry.expiresAt())
        || !MessageDigest.isEqual(
            entry.account().getBytes(StandardCharsets.UTF_8),
            account.getBytes(StandardCharsets.UTF_8))) {
      return false;
    }
    return tokens.remove(key, entry);
  }

  /** Records a reset request and tells whether the requester is still under the rate limit. */
  public boolean allowRequest(String requester) {
    Instant now = clock.instant();
    Deque<Instant> recent =
        requests.computeIfAbsent(String.valueOf(requester), k -> new ArrayDeque<>());
    synchronized (recent) {
      while (!recent.isEmpty() && !recent.peekFirst().isAfter(now.minus(RATE_WINDOW))) {
        recent.pollFirst();
      }
      if (recent.size() >= MAX_REQUESTS_PER_WINDOW) {
        return false;
      }
      recent.addLast(now);
      return true;
    }
  }

  void clear() {
    tokens.clear();
    requests.clear();
  }

  int size() {
    return tokens.size();
  }

  private void purgeExpired() {
    Instant now = clock.instant();
    tokens.values().removeIf(e -> !now.isBefore(e.expiresAt()));
  }

  private static String hash(String token) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256")
                  .digest(token.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
