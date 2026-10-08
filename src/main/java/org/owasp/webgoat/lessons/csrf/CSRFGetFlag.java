/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by jason on 9/30/17.
 *
 * <p>The endpoint used to hand out a flag whenever the request came from another site (foreign or
 * missing Referer), i.e. it rewarded a forged cross-site request. It now verifies the origin of
 * the request (Origin, falling back to Referer) against the target host and refuses requests that
 * are cross-site or cannot be verified. A flag is never issued for a forged request.
 */
@RestController
public class CSRFGetFlag {

  @Autowired LessonSession userSessionData;
  @Autowired private PluginMessages pluginMessages;

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {
    Map<String, Object> response = new HashMap<>();
    // Never let a previously issued value be confirmed after this point.
    userSessionData.setValue("csrf-get-success", null);

    String message =
        SameOriginCheck.isSameOrigin(req)
            ? "Appears the request came from the original host"
            : pluginMessages.getMessage("csrf-get.rejected");
    response.put("success", false);
    response.put("lessonCompleted", false);
    response.put("message", message);
    response.put("feedback", message);
    response.put("flag", null);
    return response;
  }
}
