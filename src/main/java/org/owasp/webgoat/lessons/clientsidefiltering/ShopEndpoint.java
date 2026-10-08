/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import java.util.List;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Coupon lookup for the shop. The coupon catalogue lives on the server only: it used to contain an
 * internal 100% "get it for free" code that was sent to every client by the coupon listing and the
 * lookup endpoint. There is no such customer-facing code anymore; only the public promotion codes
 * exist, and the checkout validates codes against this server-side catalogue.
 *
 * @author nbaars
 * @since 4/6/17.
 */
@RestController
@RequestMapping("/clientSideFiltering/challenge-store")
public class ShopEndpoint {

  @AllArgsConstructor
  private static class CheckoutCodes {

    @Getter private List<CheckoutCode> codes;
  }

  @AllArgsConstructor
  @Getter
  static class CheckoutCode {
    private String code;
    private int discount;
  }

  /** Public promotion codes; none of them makes the product free. */
  private static final List<CheckoutCode> PUBLIC_CODES =
      List.of(
          new CheckoutCode("webgoat", 25),
          new CheckoutCode("owasp", 25),
          new CheckoutCode("owasp-webgoat", 50));

  /** Server-side lookup of a coupon; unknown codes have no discount. */
  static Optional<CheckoutCode> findCoupon(String code) {
    if (code == null) {
      return Optional.empty();
    }
    return PUBLIC_CODES.stream().filter(c -> c.getCode().equals(code)).findFirst();
  }

  @GetMapping(value = "/coupons/{code}", produces = MediaType.APPLICATION_JSON_VALUE)
  public CheckoutCode getDiscountCode(@PathVariable String code) {
    return findCoupon(code).orElse(new CheckoutCode("no", 0));
  }

  @GetMapping(value = "/coupons", produces = MediaType.APPLICATION_JSON_VALUE)
  public CheckoutCodes all() {
    return new CheckoutCodes(PUBLIC_CODES);
  }
}
