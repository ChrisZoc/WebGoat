/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.apache.logging.log4j.util.Strings;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogSpoofingTask implements AssignmentEndpoint {

  @PostMapping("/LogSpoofing/log-spoofing")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username)) {
      return failed(this).output(username).build();
    }
    // CR and LF are encoded before the value is logged, so a user name can no longer start a
    // new, fabricated log line; the value is HTML-encoded too, since the log viewer renders it
    username =
        org.springframework.web.util.HtmlUtils.htmlEscape(
            username.replace("\r", "\\r").replace("\n", "\\n"));
    if (username.contains("<p>") || username.contains("<div>")) {
      return failed(this).output("Try to think of something simple ").build();
    }
    // A forged entry needs an actual line break in front of it. indexOf() returns -1 when
    // there is none, which used to count as "before admin" and so as a forged line.
    int lineBreak = username.indexOf("<br/>");
    if (lineBreak >= 0 && lineBreak < username.indexOf("admin")) {
      return success(this).output(username).build();
    }
    return failed(this).output(username).build();
  }
}
