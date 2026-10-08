/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge8;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class Assignment8 implements AssignmentEndpoint {

  private static final Map<Integer, Integer> votes = new HashMap<>();

  static {
    votes.put(1, 400);
    votes.put(2, 120);
    votes.put(3, 140);
    votes.put(4, 150);
    votes.put(5, 300);
  }

  @GetMapping(value = "/challenge/8/vote/{stars}", produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity<?> vote(@PathVariable(value = "stars") int nrOfStars) {
    // Authorization must not depend on the HTTP verb: Spring also routes HEAD (and other
    // implicit methods) here, so every request gets the same answer until a real login exists.
    var json =
        Map.of("error", true, "message", "Sorry but you need to login first in order to vote");
    return ResponseEntity.status(200).body(json);
  }

  @GetMapping("/challenge/8/votes/")
  public ResponseEntity<?> getVotes() {
    return ResponseEntity.ok(
        votes.entrySet().stream()
            .collect(Collectors.toMap(e -> "" + e.getKey(), e -> e.getValue())));
  }

  @GetMapping("/challenge/8/votes/average")
  public ResponseEntity<Map<String, Integer>> average() {
    int totalNumberOfVotes = votes.values().stream().mapToInt(i -> i.intValue()).sum();
    int categories =
        votes.entrySet().stream()
            .mapToInt(e -> e.getKey() * e.getValue())
            .reduce(0, (a, b) -> a + b);
    var json = Map.of("average", (int) Math.ceil((double) categories / totalNumberOfVotes));
    return ResponseEntity.ok(json);
  }

  @GetMapping("/challenge/8/notUsed")
  public AttackResult notUsed() {
    throw new IllegalStateException("Should never be called, challenge specific method");
  }
}
