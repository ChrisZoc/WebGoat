/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.springframework.util.StringUtils.hasText;

import jakarta.servlet.http.HttpServletResponse;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
@AssignmentHints({
  "password-reset-hint1",
  "password-reset-hint2",
  "password-reset-hint3",
  "password-reset-hint4",
  "password-reset-hint5",
  "password-reset-hint6"
})
public class ResetLinkAssignment implements AssignmentEndpoint {

  private static final String VIEW_FORMATTER = "lessons/passwordreset/templates/%s.html";
  static final String TOM_EMAIL = "tom@webgoat-cloud.org";

  // The link is the configured WebGoat base URL plus the token (see
  // ResetLinkAssignmentForgotPassword); nothing in it comes from the request.
  static final String TEMPLATE =
      """
      Hi, you requested a password reset link, please use this <a target='_blank'
       href='%s'>link</a> to reset your password. The link can be used once and expires in 15
       minutes.

      If you did not request this password change you can ignore this message.
      If you have any comments or questions, please do not hesitate to reach us at
       support@webgoat-cloud.org

      Kind regards,
      Team WebGoat
      """;

  private final ResetTokenStore tokenStore;

  public ResetLinkAssignment(ResetTokenStore tokenStore) {
    this.tokenStore = tokenStore;
  }

  @PostMapping("/PasswordReset/reset/login")
  @ResponseBody
  public AttackResult login(
      @RequestParam String password, @RequestParam String email, @CurrentUsername String username) {
    // Tom's password can only be changed with a reset token issued for Tom's account, which is
    // delivered to Tom's own mailbox and can only be redeemed by Tom. Nobody else can have changed
    // it, so a login as Tom with an attacker-chosen password never succeeds.
    if (TOM_EMAIL.equalsIgnoreCase(String.valueOf(email).trim())) {
      return failed(this).feedback("login_failed").build();
    }
    return failed(this).feedback("login_failed.tom").build();
  }

  @GetMapping("/PasswordReset/reset/reset-password/{link}")
  public ModelAndView resetPassword(
      @PathVariable(value = "link") String link, Model model, HttpServletResponse response) {
    noLeakHeaders(response);
    ModelAndView modelAndView = new ModelAndView();
    if (tokenStore.isValid(link)) {
      // Only renders the form; the token is checked again and consumed on the POST below.
      PasswordChangeForm form = new PasswordChangeForm();
      form.setResetLink(link);
      model.addAttribute("form", form);
      modelAndView.addObject("form", form);
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_reset"));
    } else {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
    }
    return modelAndView;
  }

  @PostMapping("/PasswordReset/reset/change-password")
  public ModelAndView changePassword(
      @ModelAttribute("form") PasswordChangeForm form,
      BindingResult bindingResult,
      @CurrentUsername String username,
      HttpServletResponse response) {
    noLeakHeaders(response);
    ModelAndView modelAndView = new ModelAndView();
    if (!hasText(form.getPassword())) {
      bindingResult.rejectValue("password", "not.empty");
    }
    if (bindingResult.hasErrors()) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_reset"));
      return modelAndView;
    }
    // The token (sent in the POST body) must be valid, unexpired, unused and issued for the account
    // that is redeeming it; it is consumed atomically. A token for Tom never works from another
    // user's session, even if it was intercepted.
    if (!tokenStore.consume(form.getResetLink(), username)) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
      return modelAndView;
    }
    modelAndView.setViewName(VIEW_FORMATTER.formatted("success"));
    return modelAndView;
  }

  private static void noLeakHeaders(HttpServletResponse response) {
    response.setHeader("Referrer-Policy", "no-referrer");
    response.setHeader("Cache-Control", "no-store");
  }
}
