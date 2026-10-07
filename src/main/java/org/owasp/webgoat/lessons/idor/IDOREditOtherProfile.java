/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

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

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    // Authorisation first: a profile is edited only by its owner. The id in the path and the
    // one in the body are both chosen by the caller, so neither decides anything on its own
    boolean ownsPath = authUserId != null && authUserId.equals(userId);
    boolean ownsBody =
        userSubmittedProfile.getUserId() == null
            || userSubmittedProfile.getUserId().equals(authUserId);
    if (!ownsPath || !ownsBody) {
      return failed(this).feedback("idor.edit.profile.failure4").build();
    }

    // The owner may change their own preferences, never their role: privilege is assigned
    // by the application, not taken from the request body
    UserProfile currentUserProfile = new UserProfile(userId);
    currentUserProfile.setColor(userSubmittedProfile.getColor());
    userSessionData.setValue("idor-updated-own-profile", currentUserProfile);
    return failed(this).feedback("idor.edit.profile.failure4").build();
  }
}
