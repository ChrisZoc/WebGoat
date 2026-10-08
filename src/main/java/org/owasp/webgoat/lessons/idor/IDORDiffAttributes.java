/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.idorDiffAttributes1",
  "idor.hints.idorDiffAttributes2",
  "idor.hints.idorDiffAttributes3"
})
public class IDORDiffAttributes implements AssignmentEndpoint {

  /** Attributes the profile screen renders (see idor.js). */
  private static final Set<String> DISPLAYED_ATTRIBUTES = Set.of("name", "color", "size");

  @PostMapping("/IDOR/diff-attributes")
  @ResponseBody
  public AttackResult completed(@RequestParam String attributes) {
    Set<String> submitted =
        Arrays.stream(attributes.split(","))
            .map(a -> a.trim().toLowerCase(Locale.ROOT))
            .filter(a -> !a.isEmpty())
            .collect(Collectors.toSet());
    if (submitted.isEmpty()) {
      return failed(this).feedback("idor.diff.attributes.missing").build();
    }
    // The answer is checked against what the profile endpoint really sends. Internal attributes
    // such as the role are no longer part of the response, so they cannot be "discovered".
    Set<String> exposed =
        new UserProfile(IDORLogin.TOM_USER_ID)
            .profileToMap().keySet().stream()
                .map(a -> a.toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
    if (!exposed.containsAll(submitted)) {
      return failed(this).feedback("idor.diff.not.exposed").build();
    }
    Set<String> hidden = new HashSet<>(exposed);
    hidden.removeAll(DISPLAYED_ATTRIBUTES);
    if (submitted.equals(hidden)) {
      return success(this).feedback("idor.diff.success").build();
    }
    return failed(this).feedback("idor.diff.failure").build();
  }
}
