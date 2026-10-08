/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.token.Sha512DigestUtils;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
class ProfileUploadRetrievalTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void traversalIsRefusedAndPredictableAnswerIsNotAccepted() throws Exception {
    // Encoded traversal sequences are decoded before validation and refused
    var uri = new URI("/PathTraversal/random-picture?id=%2E%2E%2F%2E%2E%2F");
    mockMvc
        .perform(get(uri))
        .andExpect(status().is(200))
        .andExpect(content().string("Illegal characters are not allowed in the query params"));

    uri = new URI("/PathTraversal/random-picture?id=%2E%2E%2F%2E%2E%2Fpath-traversal-secret");
    mockMvc
        .perform(get(uri))
        .andExpect(status().is(200))
        .andExpect(content().string("Illegal characters are not allowed in the query params"));

    uri = new URI("/PathTraversal/random-picture?id=..%252F..%252Fpath-traversal-secret");
    mockMvc
        .perform(get(uri))
        .andExpect(status().is(200))
        .andExpect(content().string(not(containsString("You found it"))));

    // The answer is no longer derivable from the username: the SHA-512 of it is refused
    mockMvc
        .perform(post("/PathTraversal/random").param("secret", Sha512DigestUtils.shaHex("test")))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.assignment", equalTo("ProfileUploadRetrieval")))
        .andExpect(jsonPath("$.lessonCompleted", is(false)));

    mockMvc
        .perform(post("/PathTraversal/random"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  void shouldReceiveRandomPicture() throws Exception {
    mockMvc
        .perform(get("/PathTraversal/random-picture"))
        .andExpect(status().is(200))
        .andExpect(header().exists("Location"))
        .andExpect(header().string("Location", containsString("?id=")))
        .andExpect(content().contentTypeCompatibleWith(MediaType.IMAGE_JPEG));
  }

  @Test
  void unknownFileDoesNotDiscloseDirectoryContents() throws Exception {
    mockMvc
        .perform(get("/PathTraversal/random-picture?id=99"))
        .andExpect(status().is(200))
        .andExpect(content().string("Picture not found"));
  }
}
