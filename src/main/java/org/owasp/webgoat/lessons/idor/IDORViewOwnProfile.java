/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import java.util.LinkedHashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class IDORViewOwnProfile {

  private final LessonSession userSessionData;

  public IDORViewOwnProfile(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @GetMapping(
      path = {"/IDOR/own", "/IDOR/profile"},
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke() {
    Map<String, Object> details = new LinkedHashMap<>();
    try {
      if ("tom".equals(userSessionData.getValue("idor-authenticated-as"))) {
        // going to use session auth to view this one
        String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
        // only the client-facing attributes; the role stays on the server
        details.putAll(new UserProfile(authUserId).profileToMap());
      } else {
        details.put(
            "error",
            "You do not have privileges to view the profile. Authenticate as tom first please.");
      }
    } catch (Exception ex) {
      log.error("something went wrong: {}", ex.getMessage());
    }
    return details;
  }
}
