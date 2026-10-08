/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss.stored;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.owasp.webgoat.lessons.xss.DOMCrossSiteScripting;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 11/23/16. */
@RestController
public class StoredCrossSiteScriptingVerifier implements AssignmentEndpoint {

  private final LessonSession lessonSession;

  public StoredCrossSiteScriptingVerifier(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/CrossSiteScriptingStored/stored-xss-follow-up")
  @ResponseBody
  public AttackResult completed(@RequestParam(required = false) String successMessage) {
    // The expected value used to be whatever the phone-home endpoint handed to any caller that
    // sent a spoofable header, so replaying that response solved this follow-up without any stored
    // XSS. Only a value the server actually issued and kept secret counts, it is single use, and
    // it is compared in constant time.
    Object issued = lessonSession.getValue(DOMCrossSiteScripting.SECRET_KEY);
    lessonSession.setValue(DOMCrossSiteScripting.SECRET_KEY, null);

    if (issued instanceof String answer
        && successMessage != null
        && MessageDigest.isEqual(
            answer.getBytes(StandardCharsets.UTF_8),
            successMessage.getBytes(StandardCharsets.UTF_8))) {
      return success(this).feedback("xss-stored-callback-success").build();
    } else {
      return failed(this).feedback("xss-stored-callback-failure").build();
    }
  }
}
