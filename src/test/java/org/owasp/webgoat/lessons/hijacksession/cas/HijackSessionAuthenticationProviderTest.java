/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.owasp.webgoat.lessons.hijacksession.cas.Authentication.AuthenticationBuilder;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

class HijackSessionAuthenticationProviderTest {

  HijackSessionAuthenticationProvider provider = new HijackSessionAuthenticationProvider();

  @ParameterizedTest
  @DisplayName("Provider authentication test")
  @MethodSource("authenticationForCookieValues")
  void testProviderAuthenticationGeneratesCookie(Authentication authentication) {
    Authentication auth = provider.authenticate(authentication);
    assertThat(auth.getId(), not(StringUtils.isEmpty(auth.getId())));
  }

  @Test
  void testAuthenticated() {
    String id = "anyId";
    provider.addSession(id);

    Authentication auth = provider.authenticate(Authentication.builder().id(id).build());

    assertThat(auth.getId(), is(id));
    assertThat(auth.isAuthenticated(), is(true));

    auth = provider.authenticate(Authentication.builder().id("otherId").build());

    assertThat(auth.getId(), is("otherId"));
    assertThat(auth.isAuthenticated(), is(false));
  }

  @Test
  void testAuthenticationToString() {
    AuthenticationBuilder authBuilder =
        Authentication.builder()
            .name("expectedName")
            .credentials("expectedCredentials")
            .id("expectedId");

    Authentication auth = authBuilder.build();

    String expected =
        "Authentication.AuthenticationBuilder("
            + "name="
            + auth.getName()
            + ", credentials="
            + auth.getCredentials()
            + ", id="
            + auth.getId()
            + ")";

    assertThat(authBuilder.toString(), is(expected));

    expected =
        "Authentication(authenticated="
            + auth.isAuthenticated()
            + ", name="
            + auth.getName()
            + ", credentials="
            + auth.getCredentials()
            + ", id="
            + auth.getId()
            + ")";

    assertThat(auth.toString(), is(expected));
  }

  @Test
  void sessionIdsHaveNoCounterOrTimestamp() {
    long before = System.currentTimeMillis();
    var ids =
        Stream.generate(() -> provider.authenticate(null).getId()).limit(200).distinct().toList();
    long after = System.currentTimeMillis();

    assertThat(ids.size(), is(200));
    for (int i = 1; i < ids.size(); i++) {
      String[] previous = ids.get(i - 1).split("-");
      String[] current = ids.get(i).split("-");
      long delta = Long.parseLong(current[0]) - Long.parseLong(previous[0]);
      // the old scheme was <previous + 1>-<epoch millis>
      assertThat(delta == 1 || delta == 2, is(false));
      long secondPart = Long.parseLong(current[1]);
      assertThat(secondPart >= before && secondPart <= after, is(false));
    }
  }

  @Test
  void guessedNeighbourIdIsNotAuthenticated() {
    String issued = provider.authenticate(null).getId();
    long counter = Long.parseLong(issued.split("-")[0]);
    long now = System.currentTimeMillis();

    for (long ts = now - 50; ts <= now + 50; ts++) {
      for (long id = counter - 2; id <= counter + 2; id++) {
        Authentication guess = Authentication.builder().id(id + "-" + ts).build();
        assertThat(provider.authenticate(guess).isAuthenticated(), is(false));
      }
    }
  }

  @Test
  void testMaxSessions() {
    for (int i = 0; i <= HijackSessionAuthenticationProvider.MAX_SESSIONS + 1; i++) {
      provider.authorizedUserAutoLogin();
      provider.addSession(null);
    }

    assertThat(provider.getSessionsSize(), is(HijackSessionAuthenticationProvider.MAX_SESSIONS));
  }

  private static Stream<Arguments> authenticationForCookieValues() {
    return Stream.of(
        Arguments.of((Object) null),
        Arguments.of(Authentication.builder().name("any").credentials("any").build()),
        Arguments.of(Authentication.builder().id("any").build()));
  }
}
