/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.Locale;
import java.util.Set;
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

  /**
   * Admin menu entries that used to be shipped to every client and merely hidden with CSS. They
   * are no longer part of the page for non-admin users (the admin functions behind them are
   * protected by server-side role checks), so there is nothing hidden left to find.
   */
  private static final Set<String> ADMIN_MENU_ITEMS = Set.of("users", "config");

  @PostMapping(
      path = "/access-control/hidden-menu",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(String hiddenMenu1, String hiddenMenu2) {
    if (isAdminMenuItem(hiddenMenu1) || isAdminMenuItem(hiddenMenu2)) {
      return failed(this).output("").feedback("access-control.hidden-menus.not-exposed").build();
    }
    return failed(this).feedback("access-control.hidden-menus.failure").output("").build();
  }

  private static boolean isAdminMenuItem(String item) {
    return item != null && ADMIN_MENU_ITEMS.contains(item.trim().toLowerCase(Locale.ROOT));
  }
}
