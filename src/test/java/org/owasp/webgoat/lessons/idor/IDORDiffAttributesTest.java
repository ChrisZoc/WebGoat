/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.session.LessonSession;

class IDORDiffAttributesTest {

  @Test
  void ownProfileResponseDoesNotExposeRole() {
    LessonSession session = new LessonSession();
    session.setValue("idor-authenticated-as", "tom");
    session.setValue("idor-authenticated-user-id", IDORLogin.TOM_USER_ID);

    var profile = new IDORViewOwnProfile(session).invoke();

    assertThat(profile).containsEntry("userId", IDORLogin.TOM_USER_ID);
    assertThat(profile).doesNotContainKeys("role", "isAdmin", "admin");
  }

  @Test
  void roleIsNoLongerAnExposedAttribute() {
    var result = new IDORDiffAttributes().completed("userId,role");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("idor.diff.not.exposed");
  }

  @Test
  void reversedOrderIsRefusedAsWell() {
    assertThat(new IDORDiffAttributes().completed("role, userId").assignmentSolved()).isFalse();
  }

  @Test
  void displayedAttributesAreNotTheDifference() {
    assertThat(new IDORDiffAttributes().completed("name,color").assignmentSolved()).isFalse();
  }
}
