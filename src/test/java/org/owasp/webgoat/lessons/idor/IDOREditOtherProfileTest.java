/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.session.LessonSession;

class IDOREditOtherProfileTest {

  private static LessonSession tomSession() {
    LessonSession session = new LessonSession();
    session.setValue("idor-authenticated-as", "tom");
    session.setValue("idor-authenticated-user-id", IDORLogin.TOM_USER_ID);
    return session;
  }

  private static UserProfile escalation(String userId) {
    UserProfile profile = new UserProfile();
    profile.setUserId(userId);
    profile.setName("Buffalo Bill");
    profile.setColor("red");
    profile.setSize("large");
    profile.setRole(1);
    return profile;
  }

  @Test
  void editingAnotherUsersProfileIsRefused() {
    LessonSession session = tomSession();

    var result = new IDOREditOtherProfile(session).completed("2342388", escalation("2342388"));

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("idor.profile.access.denied");
    assertThat(result.getOutput()).isNull();
    assertThat(session.getValue("idor-updated-other-profile")).isNull();
  }

  @Test
  void mismatchedPathAndBodyIdsAreRefused() {
    var result =
        new IDOREditOtherProfile(tomSession())
            .completed(IDORLogin.TOM_USER_ID, escalation("2342388"));

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("idor.profile.access.denied");
  }

  @Test
  void ownRoleCannotBeRaised() {
    var result =
        new IDOREditOtherProfile(tomSession())
            .completed(IDORLogin.TOM_USER_ID, escalation(IDORLogin.TOM_USER_ID));

    assertThat(result.assignmentSolved()).isFalse();
  }

  @Test
  void unauthenticatedCallerGetsRegularRefusal() {
    var result =
        new IDOREditOtherProfile(new LessonSession()).completed("2342388", escalation("2342388"));

    assertThat(result.assignmentSolved()).isFalse();
  }
}
