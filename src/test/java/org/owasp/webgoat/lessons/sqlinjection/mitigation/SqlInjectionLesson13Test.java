/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * @author nbaars
 * @since 5/21/17.
 */
public class SqlInjectionLesson13Test extends LessonTest {

  @Test
  public void knownAccountShouldDisplayData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "id"))
        .andExpect(status().isOk());
  }

  @Test
  public void allowedColumnIsUsedForOrdering() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "hostname"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-acc")));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "CASE WHEN (SELECT ip FROM servers WHERE hostname='webgoat-prd') LIKE '104.%' THEN hostname"
            + " ELSE id END",
        "case when (select ip from servers where hostname='webgoat-prd' and substr(ip,1,1) = '1')"
            + " IS NOT NULL then hostname else id end",
        "(case when (true) then hostname else id end)",
        "unknown"
      })
  public void expressionsInOrderByAreIgnored(String column) throws Exception {
    // anything that is not an allow-listed column name falls back to the default order (by id),
    // so the ordering can no longer be used as a boolean oracle
    mockMvc
        .perform(MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", column))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-dev")));
  }

  @Test
  public void postingCorrectAnswerShouldPassTheLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionMitigations/attack12a")
                .param("ip", "104.130.219.202"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  public void postingWrongAnswerShouldNotPassTheLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionMitigations/attack12a")
                .param("ip", "192.168.219.202"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}
