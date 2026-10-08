/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.SQLException;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class SqlInjectionLesson6b implements AssignmentEndpoint {
  private final LessonDataSource dataSource;

  public SqlInjectionLesson6b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/attack6b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid_6b) {
    String password = getPassword();
    // no fallback value: if the password cannot be read nothing matches
    if (password != null
        && MessageDigest.isEqual(
            password.getBytes(StandardCharsets.UTF_8),
            userid_6b.getBytes(StandardCharsets.UTF_8))) {
      return success(this).build();
    }
    return failed(this).build();
  }

  /**
   * Dave's password is random per lesson schema (see migration V2026_10_08_42), so the well-known
   * value from the original data set no longer passes.
   */
  protected String getPassword() {
    try (Connection connection = dataSource.getConnection();
        var statement =
            connection.prepareStatement(
                "SELECT password FROM user_system_data WHERE user_name = ?")) {
      statement.setString(1, "dave");
      try (var results = statement.executeQuery()) {
        return results.next() ? results.getString("password") : null;
      }
    } catch (SQLException e) {
      log.error("Unable to read the password", e);
      return null;
    }
  }
}
