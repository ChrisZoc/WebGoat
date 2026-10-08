/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.apache.logging.log4j.util.Strings;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class LogSpoofingTask implements AssignmentEndpoint {

  @PostMapping("/LogSpoofing/log-spoofing")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username)) {
      return failed(this).output(username).build();
    }
    // The username is written to the log as a single line: CR/LF are encoded so the input cannot
    // start a forged log entry, and the value is HTML-encoded before it is displayed.
    return failed(this).output(sanitizeForLog(username)).build();
  }

  static String sanitizeForLog(String value) {
    return HtmlUtils.htmlEscape(value.replace("\r", "\\r").replace("\n", "\\n"));
  }
}
