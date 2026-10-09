/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

class HijackSessionAuthenticationProviderTest {

  private static final String ID_FORMAT = "[0-9]+-[0-9]+-[0-9a-f]{32}";

  HijackSessionAuthenticationProvider provider = new HijackSessionAuthenticationProvider();

  @ParameterizedTest
  @MethodSource("authenticationForCookieValues")
  void providerAlwaysReturnsAnId(Authentication authentication) {
    Authentication auth = provider.authenticate(authentication);
    assertThat(auth.getId()).isNotEmpty();
  }

  @Test
  void idsEndInARandomSecret() {
    Set<String> secrets = new HashSet<>();
    for (int i = 0; i < 200; i++) {
      String id = HijackSessionAuthenticationProvider.AUTHENTICATION_SUPPLIER.get().getId();
      assertThat(id).matches(ID_FORMAT);
      secrets.add(id.substring(id.lastIndexOf('-') + 1));
    }
    assertThat(secrets).hasSize(200);
  }

  @Test
  void onlyTheCompleteIdAuthenticates() {
    String id = HijackSessionAuthenticationProvider.AUTHENTICATION_SUPPLIER.get().getId();
    provider.addSession(id);

    assertThat(provider.authenticate(Authentication.builder().id(id).build()).isAuthenticated())
        .isTrue();

    // the "<sequence>-<timestamp>" part alone, or with another secret, is worthless
    String prefix = id.substring(0, id.lastIndexOf('-'));
    assertThat(provider.authenticate(Authentication.builder().id(prefix).build()).isAuthenticated())
        .isFalse();
    Authentication forged = Authentication.builder().id(prefix + "-" + "0".repeat(32)).build();
    assertThat(provider.authenticate(forged).isAuthenticated()).isFalse();
  }

  @Test
  void predictedNeighbourIdsDoNotAuthenticate() {
    // the attack: find a gap in the sequence and try every timestamp inside it
    String previous = provider.authenticate(null).getId();
    for (int i = 0; i < 100; i++) {
      provider.authorizedUserAutoLogin();
    }
    String next = provider.authenticate(null).getId();
    String[] p = previous.split("-");
    String[] n = next.split("-");
    long from = Long.parseLong(p[1]);
    long to = Long.parseLong(n[1]);
    for (long seq = Long.parseLong(p[0]) + 1; seq < Long.parseLong(n[0]); seq++) {
      for (long ts = from; ts <= to; ts++) {
        Authentication guess = Authentication.builder().id(seq + "-" + ts).build();
        assertThat(provider.authenticate(guess).isAuthenticated()).isFalse();
      }
    }
  }

  @Test
  void sessionPoolIsBounded() {
    for (int i = 0; i <= HijackSessionAuthenticationProvider.MAX_SESSIONS + 10; i++) {
      provider.addSession("id-" + i);
    }
    provider.addSession(null);
    assertThat(provider.getSessionsSize())
        .isEqualTo(HijackSessionAuthenticationProvider.MAX_SESSIONS);
  }

  private static Stream<Arguments> authenticationForCookieValues() {
    return Stream.of(
        Arguments.of((Object) null),
        Arguments.of(Authentication.builder().name("any").credentials("any").build()),
        Arguments.of(Authentication.builder().id("any").build()));
  }
}
