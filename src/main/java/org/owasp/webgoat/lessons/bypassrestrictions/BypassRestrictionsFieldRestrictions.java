/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.Set;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The restrictions of the HTML form (select / radio options, checkbox, maxlength, readonly) are
 * enforced again on the server. A request whose values could not have been produced by the form is
 * rejected instead of being accepted.
 */
@RestController
public class BypassRestrictionsFieldRestrictions implements AssignmentEndpoint {

  private static final Set<String> ALLOWED_OPTIONS = Set.of("option1", "option2");
  private static final Set<String> ALLOWED_CHECKBOX = Set.of("on", "off");
  private static final int SHORT_INPUT_MAX_LENGTH = 5;
  private static final String READ_ONLY_VALUE = "change";

  @PostMapping("/BypassRestrictions/FieldRestrictions")
  @ResponseBody
  public AttackResult completed(
      @RequestParam(required = false) String select,
      @RequestParam(required = false) String radio,
      @RequestParam(required = false) String checkbox,
      @RequestParam(required = false) String shortInput,
      @RequestParam(required = false) String readOnlyInput) {
    // An unchecked checkbox is simply not submitted by the browser.
    String checkboxValue = checkbox == null ? "off" : checkbox;
    boolean valid =
        select != null
            && ALLOWED_OPTIONS.contains(select)
            && radio != null
            && ALLOWED_OPTIONS.contains(radio)
            && ALLOWED_CHECKBOX.contains(checkboxValue)
            && shortInput != null
            && shortInput.length() <= SHORT_INPUT_MAX_LENGTH
            && READ_ONLY_VALUE.equals(readOnlyInput);
    if (!valid) {
      return failed(this).feedback("bypass-restrictions.rejected").build();
    }
    return failed(this).build();
  }
}
