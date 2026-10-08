/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.session.LessonSession;

class IDORViewOtherProfileTest {

  private static LessonSession tomSession() {
    LessonSession session = new LessonSession();
    session.setValue("idor-authenticated-as", "tom");
    session.setValue("idor-authenticated-user-id", IDORLogin.TOM_USER_ID);
    return session;
  }

  @Test
  void otherUsersProfileIsNotReturned() {
    var result = new IDORViewOtherProfile(tomSession()).completed("2342388");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("idor.profile.access.denied");
    assertThat(result.getOutput()).isNull();
  }

  @Test
  void unknownIdsAreRefusedTheSameWay() {
    var result = new IDORViewOtherProfile(tomSession()).completed("1");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("idor.profile.access.denied");
  }

  @Test
  void ownProfileIdIsNotACompletion() {
    var result = new IDORViewOtherProfile(tomSession()).completed(IDORLogin.TOM_USER_ID);

    assertThat(result.assignmentSolved()).isFalse();
  }

  @Test
  void unauthenticatedCallerGetsRegularRefusal() {
    var result = new IDORViewOtherProfile(new LessonSession()).completed("2342388");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("idor.view.other.profile.failure1");
  }
}
