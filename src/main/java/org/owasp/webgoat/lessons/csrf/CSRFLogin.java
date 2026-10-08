/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import jakarta.servlet.http.HttpServletRequest;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The assignment used to be completed whenever the current session belonged to a "csrf-" account,
 * i.e. whenever a victim had been silently logged in to the attacker's account by a forged login
 * form (login CSRF).
 *
 * <p>A session is now only trusted when its login request was verifiably same-origin (recorded by
 * {@link LoginOriginRecorder}). A session established by a cross-site or unverifiable login is
 * refused. A same-origin login is the user's own deliberate action, not a forged one, so the
 * assignment is not completed in that case either.
 */
@RestController
@AssignmentHints({"csrf-login-hint1", "csrf-login-hint2", "csrf-login-hint3"})
public class CSRFLogin implements AssignmentEndpoint {

  @PostMapping(
      path = "/csrf/login",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(@CurrentUsername String username, HttpServletRequest request) {
    if (!LoginOriginRecorder.loginOriginVerified(request)) {
      return failed(this).feedback("csrf-login-untrusted-session").feedbackArgs(username).build();
    }
    return failed(this).feedback("csrf-login-failed").feedbackArgs(username).build();
  }
}
