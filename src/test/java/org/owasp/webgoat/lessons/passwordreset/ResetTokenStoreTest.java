/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class ResetTokenStoreTest {

  private static class MutableClock extends Clock {
    Instant now = Instant.parse("2024-01-01T00:00:00Z");

    @Override
    public java.time.ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  @Test
  void tokensAreRandomBoundSingleUseAndExpire() {
    MutableClock clock = new MutableClock();
    ResetTokenStore store = new ResetTokenStore(clock);

    String a = store.issue("alice");
    String b = store.issue("bob");
    assertThat(a).isNotEqualTo(b).matches("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");

    assertThat(store.consume(a, "bob")).isFalse();
    assertThat(store.consume(a, "alice")).isTrue();
    assertThat(store.consume(a, "alice")).isFalse();

    clock.now = clock.now.plus(ResetTokenStore.TOKEN_LIFETIME).plus(Duration.ofSeconds(1));
    assertThat(store.isValid(b)).isFalse();
    assertThat(store.consume(b, "bob")).isFalse();
  }

  @Test
  void newTokenInvalidatesOlderOnes() {
    ResetTokenStore store = new ResetTokenStore();
    String first = store.issue("alice");
    String second = store.issue("alice");
    assertThat(store.isValid(first)).isFalse();
    assertThat(store.isValid(second)).isTrue();
  }
}
