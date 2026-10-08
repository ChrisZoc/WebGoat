/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The feedback endpoint used to accept a JSON document posted as {@code text/plain} (which a plain
 * HTML form on another site can send without a CORS preflight) and rewarded such a cross-site
 * request with a flag.
 *
 * <p>It now only accepts {@code application/json} bodies (a cross-site request with that content
 * type needs a CORS preflight, which is not granted) and additionally requires the request to be
 * verifiably same-origin (Origin, falling back to Referer). Forged requests are refused with a
 * normal failed AttackResult and no flag is ever issued for them.
 */
@RestController
@AssignmentHints({"csrf-feedback-hint1", "csrf-feedback-hint2", "csrf-feedback-hint3"})
public class CSRFFeedback implements AssignmentEndpoint {

  private final LessonSession userSessionData;
  private final ObjectReader feedbackReader;

  public CSRFFeedback(LessonSession userSessionData, ObjectMapper objectMapper) {
    this.userSessionData = userSessionData;
    // Use a dedicated reader instead of reconfiguring the application wide ObjectMapper.
    this.feedbackReader =
        objectMapper
            .readerFor(Map.class)
            .with(
                DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES,
                DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES,
                DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS,
                DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY,
                DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES,
                DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  }

  @PostMapping(
      value = "/csrf/feedback/message",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request, @RequestBody(required = false) String feedback) {
    if (!isJson(request.getContentType()) || !SameOriginCheck.isSameOrigin(request)) {
      return failed(this).feedback("csrf-feedback-rejected").build();
    }
    if (feedback == null) {
      return failed(this).feedback("csrf-feedback-invalid-json").build();
    }
    try {
      feedbackReader.readValue(feedback.getBytes(StandardCharsets.UTF_8));
    } catch (IOException e) {
      // Do not leak stack traces to the client.
      return failed(this).feedback("csrf-feedback-invalid-json").build();
    }
    return failed(this).feedback("csrf-feedback-received").build();
  }

  @PostMapping(path = "/csrf/feedback", produces = "application/json")
  @ResponseBody
  public AttackResult flag(@RequestParam(value = "confirmFlagVal", required = false) String flag) {
    Object expected = userSessionData.getValue("csrf-feedback");
    if (flag != null && expected != null && flag.equals(expected)) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }

  private static boolean isJson(String contentType) {
    if (contentType == null) {
      return false;
    }
    try {
      MediaType mediaType = MediaType.parseMediaType(contentType);
      return MediaType.APPLICATION_JSON.isCompatibleWith(mediaType)
          && !mediaType.isWildcardType()
          && !mediaType.isWildcardSubtype();
    } catch (InvalidMediaTypeException e) {
      return false;
    }
  }
}
