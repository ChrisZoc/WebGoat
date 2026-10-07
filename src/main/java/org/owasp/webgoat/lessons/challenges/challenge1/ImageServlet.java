/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

import java.io.IOException;
import java.util.Random;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ImageServlet {

  // The admin password's variable part. It used to be a four-digit PIN - ten thousand
  // guesses - that this servlet then wrote into the bytes of the public logo. It is now a
  // random secret that never leaves the server.
  public static final String PINCODE =
      java.util.HexFormat.of().formatHex(new java.security.SecureRandom().generateSeed(16));

  @RequestMapping(
      method = {GET, POST},
      value = "/challenge/logo",
      produces = MediaType.IMAGE_PNG_VALUE)
  @ResponseBody
  public byte[] logo() throws IOException {
    byte[] in =
        new ClassPathResource("lessons/challenges/images/webgoat2.png")
            .getInputStream()
            .readAllBytes();

    // Served unmodified: a public image is no place to hide part of a credential
    return in;
  }
}
