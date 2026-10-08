/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Checkout with a coupon code. The code is validated against the server-side coupon catalogue
 * ({@link ShopEndpoint#findCoupon(String)}); the order is only free when a valid coupon grants a
 * 100% discount. The former hard-coded "get_it_for_free" code, which was leaked to every client by
 * the coupon endpoints, no longer exists.
 *
 * @author nbaars
 * @since 4/6/17.
 */
@RestController
@AssignmentHints({
  "client.side.filtering.free.hint1",
  "client.side.filtering.free.hint2",
  "client.side.filtering.free.hint3"
})
public class ClientSideFilteringFreeAssignment implements AssignmentEndpoint {

  @PostMapping("/clientSideFiltering/getItForFree")
  @ResponseBody
  public AttackResult completed(@RequestParam(required = false) String checkoutCode) {
    boolean free =
        ShopEndpoint.findCoupon(checkoutCode).map(c -> c.getDiscount() >= 100).orElse(false);
    if (free) {
      return success(this).build();
    }
    return failed(this).build();
  }
}
