/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * @author nbaars
 * @since 5/2/17.
 */
public class ShopEndpointTest extends LessonTest {

  private MockMvc mockMvc;

  @BeforeEach
  public void setup() {
    this.mockMvc = standaloneSetup(new ShopEndpoint()).build();
  }

  @Test
  public void freeCouponIsNotExposed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/clientSideFiltering/challenge-store/coupons/get_it_for_free"))
        .andExpect(jsonPath("$.code", CoreMatchers.is("no")))
        .andExpect(jsonPath("$.discount", CoreMatchers.is(0)));
  }

  @Test
  public void getCoupon() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/clientSideFiltering/challenge-store/coupons/webgoat"))
        .andExpect(jsonPath("$.code", CoreMatchers.is("webgoat")))
        .andExpect(jsonPath("$.discount", CoreMatchers.is(25)));
  }

  @Test
  public void askForUnknownCouponCode() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get(
                "/clientSideFiltering/challenge-store/coupons/does-not-exists"))
        .andExpect(jsonPath("$.code", CoreMatchers.is("no")))
        .andExpect(jsonPath("$.discount", CoreMatchers.is(0)));
  }

  @Test
  public void fetchAllTheCouponsShouldNotContainGetItForFree() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/clientSideFiltering/challenge-store/coupons"))
        .andExpect(jsonPath("$.codes.length()", is(3)))
        .andExpect(jsonPath("$.codes[*].code", not(hasItem("get_it_for_free"))))
        .andExpect(jsonPath("$.codes[*].discount", not(hasItem(100))));
  }
}
