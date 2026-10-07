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
public class BypassRestrictionsFieldRestrictions implements AssignmentEndpoint {

  @PostMapping("/BypassRestrictions/FieldRestrictions")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String select,
      @RequestParam String radio,
      @RequestParam String checkbox,
      @RequestParam String shortInput,
      @RequestParam String readOnlyInput) {
    // The restrictions the form shows are enforced here as well: a request can carry any value
    // for any field, whatever the HTML allowed. Anything outside them is refused.
    boolean valid =
        java.util.Set.of("option1", "option2").contains(select)
            && java.util.Set.of("option1", "option2").contains(radio)
            && java.util.Set.of("on", "off").contains(checkbox)
            && shortInput.length() <= 5
            && "change".equals(readOnlyInput);
    if (!valid) {
      return failed(this).output("Rejected: values outside the allowed ones.").build();
    }
    return informationMessage(this).build();
  }
}
