/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson2Test extends LessonTest {

  @ParameterizedTest
  @ValueSource(
      strings = {
        "SELECT department FROM employees WHERE userid=96134;",
        "select department from employees where last_name='Franco'",
        "select * from user_system_data"
      })
  public void clientSuppliedSqlIsNotExecuted(String query) throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SqlInjection/attack2").param("query", query))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
        .andExpect(jsonPath("$.feedback", CoreMatchers.containsString("disabled")));
  }
}
