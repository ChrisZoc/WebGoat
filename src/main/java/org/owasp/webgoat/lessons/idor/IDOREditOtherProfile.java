/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.otherProfile1",
  "idor.hints.otherProfile2",
  "idor.hints.otherProfile3",
  "idor.hints.otherProfile4",
  "idor.hints.otherProfile5",
  "idor.hints.otherProfile6",
  "idor.hints.otherProfile7",
  "idor.hints.otherProfile8",
  "idor.hints.otherProfile9"
})
public class IDOREditOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDOREditOtherProfile(LessonSession lessonSession) {
    this.userSessionData = lessonSession;
  }

  @PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
  @ResponseBody
  public AttackResult completed(
      @PathVariable("userId") String userId, @RequestBody UserProfile userSubmittedProfile) {

    if (!"tom".equals(userSessionData.getValue("idor-authenticated-as"))) {
      return failed(this).feedback("idor.view.other.profile.failure1").build();
    }
    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    // Authorization check: the profile in the URL and in the body must both belong to the
    // authenticated user. Nobody may edit someone else's profile, and the role is never taken
    // from the request (no self-service privilege change). Nothing is modified or stored, and the
    // refusal is a regular assignment answer (200, not completed) so the lesson UI keeps working.
    boolean ownProfile =
        authUserId != null
            && authUserId.equals(userId)
            && (userSubmittedProfile.getUserId() == null
                || authUserId.equals(userSubmittedProfile.getUserId()));
    if (!ownProfile) {
      return failed(this).feedback("idor.profile.access.denied").build();
    }
    return failed(this).feedback("idor.edit.profile.failure4").build();
  }
}
