/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.regex.Pattern;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The validation done by JavaScript in the browser is repeated on the server with the same
 * patterns. The client-supplied {@code error} counter is not trusted: input that violates any
 * pattern is rejected regardless of what the client claims.
 */
@RestController
public class BypassRestrictionsFrontendValidation implements AssignmentEndpoint {

  private static final Pattern[] PATTERNS = {
    Pattern.compile("^[a-z]{3}$"),
    Pattern.compile("^[0-9]{3}$"),
    Pattern.compile("^[a-zA-Z0-9 ]*$"),
    Pattern.compile("^(one|two|three|four|five|six|seven|eight|nine)$"),
    Pattern.compile("^\\d{5}$"),
    Pattern.compile("^\\d{5}(-\\d{4})?$"),
    Pattern.compile("^[2-9]\\d{2}-?\\d{3}-?\\d{4}$")
  };

  @PostMapping("/BypassRestrictions/frontendValidation")
  @ResponseBody
  public AttackResult completed(
      @RequestParam(required = false) String field1,
      @RequestParam(required = false) String field2,
      @RequestParam(required = false) String field3,
      @RequestParam(required = false) String field4,
      @RequestParam(required = false) String field5,
      @RequestParam(required = false) String field6,
      @RequestParam(required = false) String field7,
      @RequestParam(required = false) String error) {
    String[] fields = {field1, field2, field3, field4, field5, field6, field7};
    for (int i = 0; i < fields.length; i++) {
      if (fields[i] == null || !PATTERNS[i].matcher(fields[i]).matches()) {
        return failed(this).feedback("bypass-restrictions.rejected").build();
      }
    }
    return failed(this).build();
  }
}
