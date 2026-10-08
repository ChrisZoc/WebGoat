/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.springframework.http.MediaType.ALL_VALUE;

import com.google.common.collect.Lists;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reviews used to be protected by a hard-coded "anti-CSRF" value that was identical for every user
 * (and visible in the page source), so a form on another site could post reviews on behalf of a
 * logged-in victim.
 *
 * <p>Posting a review now requires a synchronizer token that is randomly generated per session
 * (served to the page by {@code GET /csrf/review/token}, which another site cannot read) and a
 * verifiably same-origin request (Origin, falling back to Referer). Requests failing either check
 * are refused with a normal failed AttackResult and the review is not stored.
 */
@RestController
@AssignmentHints({"csrf-review-hint1", "csrf-review-hint2", "csrf-review-hint3"})
public class ForgedReviews implements AssignmentEndpoint {

  static final String REVIEW_TOKEN = "webgoat.csrf.review-token";

  private static final DateTimeFormatter fmt =
      DateTimeFormatter.ofPattern("yyyy-MM-dd, HH:mm:ss");
  private static final SecureRandom RANDOM = new SecureRandom();

  private static final Map<String, List<Review>> userReviews = new ConcurrentHashMap<>();
  private static final List<Review> REVIEWS = new ArrayList<>();

  static {
    REVIEWS.add(
        new Review("secUriTy", LocalDateTime.now().format(fmt), "This is like swiss cheese", 0));
    REVIEWS.add(new Review("webgoat", LocalDateTime.now().format(fmt), "It works, sorta", 2));
    REVIEWS.add(new Review("guest", LocalDateTime.now().format(fmt), "Best, App, Ever", 5));
    REVIEWS.add(
        new Review(
            "guest",
            LocalDateTime.now().format(fmt),
            "This app is so insecure, I didn't even post this review, can you pull that off too?",
            1));
  }

  @GetMapping(
      path = "/csrf/review",
      produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = ALL_VALUE)
  @ResponseBody
  public Collection<Review> retrieveReviews(@CurrentUsername String username) {
    Collection<Review> allReviews = Lists.newArrayList();
    Collection<Review> newReviews = userReviews.get(username);
    if (newReviews != null) {
      allReviews.addAll(newReviews);
    }

    allReviews.addAll(REVIEWS);

    return allReviews;
  }

  /** Hands the per-session anti-CSRF token to the review form of the lesson page. */
  @GetMapping(
      path = "/csrf/review/token",
      produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = ALL_VALUE)
  @ResponseBody
  public Map<String, String> reviewToken(HttpServletRequest request) {
    return Map.of("token", sessionToken(request.getSession(true)));
  }

  @PostMapping("/csrf/review")
  @ResponseBody
  public AttackResult createNewReview(
      String reviewText,
      String stars,
      String validateReq,
      HttpServletRequest request,
      @CurrentUsername String username) {
    HttpSession session = request.getSession(false);
    Object expected = session == null ? null : session.getAttribute(REVIEW_TOKEN);
    if (!(expected instanceof String expectedToken) || !tokenMatches(expectedToken, validateReq)) {
      return failed(this).feedback("csrf-review.rejected").build();
    }
    if (!SameOriginCheck.isSameOrigin(request)) {
      return failed(this).feedback("csrf-review.rejected").build();
    }

    Review review = new Review();
    review.setText(reviewText);
    review.setDateTime(LocalDateTime.now().format(fmt));
    review.setUser(username);
    review.setStars(parseStars(stars));
    userReviews.computeIfAbsent(username, u -> new ArrayList<>()).add(review);
    return failed(this).feedback("csrf-review.posted").build();
  }

  private static synchronized String sessionToken(HttpSession session) {
    Object token = session.getAttribute(REVIEW_TOKEN);
    if (token instanceof String existing) {
      return existing;
    }
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    String created = HexFormat.of().formatHex(bytes);
    session.setAttribute(REVIEW_TOKEN, created);
    return created;
  }

  private static boolean tokenMatches(String expected, String submitted) {
    return submitted != null
        && MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8), submitted.getBytes(StandardCharsets.UTF_8));
  }

  private static Integer parseStars(String stars) {
    try {
      return stars == null ? null : Integer.valueOf(stars.trim());
    } catch (NumberFormatException e) {
      return null;
    }
  }
}
