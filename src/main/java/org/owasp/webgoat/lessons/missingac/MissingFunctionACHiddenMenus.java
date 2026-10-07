/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 1/5/17. */
@RestController
@AssignmentHints({
  "access-control.hidden-menus.hint1",
  "access-control.hidden-menus.hint2",
  "access-control.hidden-menus.hint3"
})
public class MissingFunctionACHiddenMenus implements AssignmentEndpoint {

  private final MissingAccessControlUserRepository userRepository;

  public MissingFunctionACHiddenMenus(MissingAccessControlUserRepository userRepository) {
    this.userRepository = userRepository;
  }


  @PostMapping(
      path = "/access-control/hidden-menu",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(
      String hiddenMenu1,
      String hiddenMenu2,
      @org.owasp.webgoat.container.CurrentUsername String username) {
    // Hiding admin entries in the page is not access control: the functions behind them are
    // checked on the server now, and so is this - only an admin can act on the admin menu.
    var user = userRepository.findByUsername(username);
    boolean admin = user != null && user.isAdmin();
    if (admin && hiddenMenu1.equals("Users") && hiddenMenu2.equals("Config")) {
      return success(this).output("").feedback("access-control.hidden-menus.success").build();
    }

    if (hiddenMenu1.equals("Config") && hiddenMenu2.equals("Users")) {
      return failed(this).output("").feedback("access-control.hidden-menus.close").build();
    }

    return failed(this).feedback("access-control.hidden-menus.failure").output("").build();
  }
}
