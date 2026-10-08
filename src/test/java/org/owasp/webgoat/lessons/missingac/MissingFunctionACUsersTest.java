/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.hamcrest.Matchers.is;
import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class MissingFunctionACUsersTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void listingUsersRequiresAdmin() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .header("Content-type", "application/json"))
        .andExpect(status().isForbidden());
  }

  @Test
  void usersPageRequiresAdmin() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/access-control/users"))
        .andExpect(status().isForbidden());
  }

  @Test
  @WithWebGoatUser(username = "Jerry")
  void adminCanListUsers() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .header("Content-type", "application/json"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].username", CoreMatchers.is("Tom")))
        .andExpect(
            jsonPath(
                "$[0].userHash",
                CoreMatchers.is(
                    new DisplayUser(new User("Tom", "qwertyqwerty1234", false), PASSWORD_SALT_SIMPLE)
                        .getUserHash())))
        .andExpect(jsonPath("$[0].admin", CoreMatchers.is(false)));
  }

  @Test
  void addUserCannotGrantAdmin() throws Exception {
    var user =
        """
        {"username":"newUser","password":"newUser12","admin": "true"}
        """;
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/users")
                .header("Content-type", "application/json")
                .content(user))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.admin", is(false)));
  }
}
