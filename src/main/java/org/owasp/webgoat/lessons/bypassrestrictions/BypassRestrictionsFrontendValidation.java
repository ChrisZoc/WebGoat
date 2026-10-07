/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BypassRestrictionsFrontendValidation implements AssignmentEndpoint {

  @PostMapping("/BypassRestrictions/frontendValidation")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String field1,
      @RequestParam String field2,
      @RequestParam String field3,
      @RequestParam String field4,
      @RequestParam String field5,
      @RequestParam String field6,
      @RequestParam String field7,
      @RequestParam Integer error) {
    // The same rules the page checks in JavaScript, checked again on the server, which is the
    // only place they can actually be enforced. The client's own "error" count is not trusted.
    boolean valid =
        field1.matches("^[a-z]{3}$")
            && field2.matches("^[0-9]{3}$")
            && field3.matches("^[a-zA-Z0-9 ]*$")
            && field4.matches("^(one|two|three|four|five|six|seven|eight|nine)$")
            && field5.matches("^\\d{5}$")
            && field6.matches("^\\d{5}(-\\d{4})?$")
            && field7.matches("^[2-9]\\d{2}-?\\d{3}-?\\d{4}$");
    if (!valid) {
      return failed(this).output("Rejected: the submitted values do not pass validation.").build();
    }
    return informationMessage(this).build();
  }
}
