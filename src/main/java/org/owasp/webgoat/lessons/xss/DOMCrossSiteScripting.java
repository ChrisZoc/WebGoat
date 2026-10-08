/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The "phone home" endpoint used to be the callback of the DOM XSS in the {@code #test/} route: any
 * script running in the victim's page (or anybody sending the spoofable {@code
 * webgoat-requested-by} header) received a session secret and completed the assignment. The test
 * route no longer renders its parameter as HTML, and this endpoint no longer hands out secrets or
 * completes anything on the strength of a client-controlled header.
 */
@RestController
public class DOMCrossSiteScripting implements AssignmentEndpoint {

  public static final String SECRET_KEY = "randValue";

  private final LessonSession lessonSession;

  public DOMCrossSiteScripting(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping("/CrossSiteScripting/phone-home-xss")
  @ResponseBody
  public AttackResult completed(
      @RequestParam(required = false) String param1,
      @RequestParam(required = false) String param2) {
    // invalidate anything that might still be lying around from an earlier call
    lessonSession.setValue(SECRET_KEY, null);
    return failed(this)
        .feedback("xss-dom-message-failure")
        .output("phoneHome Response is disabled: injected script is no longer executed")
        .build();
  }
}
