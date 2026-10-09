/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/***
 *
 * @author Angel Olle Blazquez
 *
 */
class HijackSessionAuthenticationProviderTest {

  private static class MutableClock extends Clock {
    Instant now = Instant.parse("2024-01-01T00:00:00Z");

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  HijackSessionAuthenticationProvider provider = new HijackSessionAuthenticationProvider();

  @Test
  void idsAreRandomOpaqueAndUnique() {
    var ids =
        Stream.generate(() -> provider.login("u", "tom", "pw").getId())
            .limit(500)
            .distinct()
            .toList();
    assertThat(ids).hasSize(500).allMatch(id -> id.matches("[A-Za-z0-9_-]{43}"));
  }

  @Test
  void sessionOnlyValidForItsOwnPrincipal() {
    String id = provider.login("alice", "tom", "pw").getId();
    assertThat(provider.resume("alice", "tom", id).isAuthenticated()).isTrue();
    assertThat(provider.resume("bob", "tom", id).isAuthenticated()).isFalse();
    assertThat(provider.resume("alice", "jerry", id).isAuthenticated()).isFalse();
    assertThat(provider.resume("alice", "", id).isAuthenticated()).isFalse();
    assertThat(provider.resume("alice", "tom", "not-issued").isAuthenticated()).isFalse();
  }

  @Test
  void blankCredentialsGetNoSession() {
    assertThat(provider.login("alice", "", "").getId()).isNull();
    assertThat(provider.login("alice", "tom", " ").getId()).isNull();
    assertThat(provider.getSessionsSize()).isZero();
  }

  @Test
  void sessionsExpire() {
    MutableClock clock = new MutableClock();
    HijackSessionAuthenticationProvider p = new HijackSessionAuthenticationProvider(clock);
    String id = p.login("alice", "tom", "pw").getId();
    clock.now = clock.now.plus(HijackSessionAuthenticationProvider.IDLE_TIMEOUT);
    assertThat(p.resume("alice", "tom", id).isAuthenticated()).isFalse();
  }

  @Test
  void invalidatedSessionIsGone() {
    String id = provider.login("alice", "tom", "pw").getId();
    provider.invalidate(id);
    assertThat(provider.resume("alice", "tom", id).isAuthenticated()).isFalse();
  }
}
