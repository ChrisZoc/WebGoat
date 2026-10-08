/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.session.LessonSession;

class IDORLoginTest {

  @Test
  void publishedDefaultCredentialsAreRefused() {
    LessonSession session = new LessonSession();

    var result = new IDORLogin(session).completed("tom", "cat");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("idor.login.failure");
    assertThat(session.getValue("idor-authenticated-as")).isNull();
    assertThat(session.getValue("idor-authenticated-user-id")).isNull();
  }

  @Test
  void otherHardCodedCredentialsAreRefused() {
    LessonSession session = new LessonSession();

    assertThat(new IDORLogin(session).completed("bill", "buffalo").assignmentSolved()).isFalse();
    assertThat(new IDORLogin(session).completed("unknown", "x").assignmentSolved()).isFalse();
    assertThat(session.getValue("idor-authenticated-as")).isNull();
  }
}
