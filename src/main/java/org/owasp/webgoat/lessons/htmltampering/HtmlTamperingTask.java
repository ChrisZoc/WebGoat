/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.math.BigDecimal;
import java.math.RoundingMode;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The order used to be priced with the {@code Total} value sent by the browser, so changing the
 * hidden field bought the TV at any price.
 *
 * <p>The price now comes from the server-side catalogue only: the total is computed as unit price x
 * quantity on the server and the client-supplied total is never used for charging. A submitted
 * total that differs from the server-side total is reported as tampering and the order is refused.
 */
@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
public class HtmlTamperingTask implements AssignmentEndpoint {

  static final BigDecimal UNIT_PRICE = new BigDecimal("2999.99");
  private static final int MAX_QUANTITY = 1000;

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(
      @RequestParam(value = "QTY", required = false) String qty,
      @RequestParam(value = "Total", required = false) String total) {
    Integer quantity = parseQuantity(qty);
    if (quantity == null) {
      return failed(this).feedback("html-tampering.invalid-quantity").build();
    }
    BigDecimal serverTotal =
        UNIT_PRICE.multiply(BigDecimal.valueOf(quantity)).setScale(2, RoundingMode.HALF_UP);
    BigDecimal clientTotal = parseAmount(total);
    if (clientTotal == null || clientTotal.compareTo(serverTotal) != 0) {
      return failed(this)
          .feedback("html-tampering.tamper.rejected")
          .feedbackArgs(serverTotal.toPlainString())
          .build();
    }
    return failed(this).feedback("html-tampering.tamper.failure").build();
  }

  private static Integer parseQuantity(String qty) {
    if (qty == null) {
      return null;
    }
    try {
      int value = Integer.parseInt(qty.trim());
      return value >= 1 && value <= MAX_QUANTITY ? value : null;
    } catch (NumberFormatException e) {
      return null;
    }
  }

  private static BigDecimal parseAmount(String amount) {
    if (amount == null) {
      return null;
    }
    try {
      return new BigDecimal(amount.trim()).setScale(2, RoundingMode.HALF_UP);
    } catch (NumberFormatException | ArithmeticException e) {
      return null;
    }
  }
}
