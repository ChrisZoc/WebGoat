/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.session.LessonSession;

class IDORViewOwnProfileAltUrlTest {

  private static LessonSession tomSession() {
    LessonSession session = new LessonSession();
    session.setValue("idor-authenticated-as", "tom");
    session.setValue("idor-authenticated-user-id", IDORLogin.TOM_USER_ID);
    return session;
  }

  @Test
  void directObjectReferenceIsNotResolved() {
    var result =
        new IDORViewOwnProfileAltUrl(tomSession()).completed("WebGoat/IDOR/profile/2342384");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("idor.view.own.profile.no.direct.reference");
    assertThat(result.getOutput()).isNull();
  }

  @Test
  void otherUsersReferenceIsNotResolved() {
    var result =
        new IDORViewOwnProfileAltUrl(tomSession()).completed("WebGoat/IDOR/profile/2342388");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
  }

  @Test
  void unauthenticatedRequestIsRefusedWithoutError() {
    var result =
        new IDORViewOwnProfileAltUrl(new LessonSession()).completed("WebGoat/IDOR/profile/2342384");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("idor.view.own.profile.failure2");
  }
}
