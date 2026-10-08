/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"jwt-secret-hint1", "jwt-secret-hint2", "jwt-secret-hint3"})
public class JWTSecretKeyEndpoint implements AssignmentEndpoint {

  public static final String[] SECRETS = {
    "victory", "business", "available", "shipping", "washington"
  };
  /**
   * The only key the /JWT/secret verifier trusts: a random 512 bit key generated per server start,
   * never handed out and not derived from a dictionary word, so it cannot be brute forced.
   */
  public static final String JWT_SECRET = JwtSecrets.randomBase64Key();

  /**
   * Key of the sample token shown on the lesson page. The sample is a throw-away demo token: its
   * key is deliberately unrelated to {@link #JWT_SECRET}, so recovering it (it is a dictionary
   * word) gives no ability to forge a token the verifier accepts.
   */
  private static final String SAMPLE_TOKEN_SECRET =
      TextCodec.BASE64.encode(SECRETS[new SecureRandom().nextInt(SECRETS.length)]);
  private static final String WEBGOAT_USER = "WebGoat";
  private static final List<String> expectedClaims =
      List.of("iss", "iat", "exp", "aud", "sub", "username", "Email", "Role");

  @RequestMapping(path = "/JWT/secret/gettoken", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSecretToken() {
    return Jwts.builder()
        .setIssuer("WebGoat Token Builder")
        .setAudience("webgoat.org")
        .setIssuedAt(Calendar.getInstance().getTime())
        .setExpiration(Date.from(Instant.now().plusSeconds(60)))
        .setSubject("tom@webgoat.org")
        .claim("username", "Tom")
        .claim("Email", "tom@webgoat.org")
        .claim("Role", new String[] {"Manager", "Project Administrator"})
        .signWith(SignatureAlgorithm.HS256, SAMPLE_TOKEN_SECRET)
        .compact();
  }

  @PostMapping("/JWT/secret")
  @ResponseBody
  public AttackResult login(@RequestParam String token) {
    try {
      Jwt jwt = Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token);
      Claims claims = (Claims) jwt.getBody();
      if (!claims.keySet().containsAll(expectedClaims)) {
        return failed(this).feedback("jwt-secret-claims-missing").build();
      } else {
        String user = (String) claims.get("username");

        if (WEBGOAT_USER.equalsIgnoreCase(user)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-secret-incorrect-user").feedbackArgs(user).build();
        }
      }
    } catch (Exception e) {
      return failed(this).feedback("jwt-invalid-token").output(e.getMessage()).build();
    }
  }
}
