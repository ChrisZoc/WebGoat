/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import java.util.LinkedHashMap;
import java.util.Map;

/** Created by jason on 1/5/17. */
public class UserProfile {
  private String userId;
  private String name;
  private String color;
  private String size;
  private boolean isAdmin;
  private int role;

  public UserProfile() {}

  public UserProfile(String id) {
    setProfileFromId(id);
  }

  //
  private void setProfileFromId(String id) {
    // emulate look up from database
    if (id.equals("2342384")) {
      this.userId = id;
      this.color = "yellow";
      this.name = "Tom Cat";
      this.size = "small";
      this.isAdmin = false;
      this.role = 3;
    } else if (id.equals("2342388")) {
      this.userId = id;
      this.color = "brown";
      this.name = "Buffalo Bill";
      this.size = "large";
      this.isAdmin = false;
      this.role = 3;
    } else {
      // not found
    }
  }

  /**
   * The profile as it is sent to the client. Only the attributes the user is meant to see are
   * included (the user's own id is needed to address the profile); internal authorization data
   * such as the role or the admin flag never leaves the server (excessive data exposure).
   */
  public Map<String, Object> profileToMap() {
    Map<String, Object> profileMap = new LinkedHashMap<>();
    profileMap.put("userId", this.userId);
    profileMap.put("name", this.name);
    profileMap.put("color", this.color);
    profileMap.put("size", this.size);
    return profileMap;
  }

  public String toHTMLString() {
    String htmlBreak = "<br/>";
    return "userId"
        + this.userId
        + htmlBreak
        + "name"
        + this.name
        + htmlBreak
        + "size"
        + this.size;
  }

  //
  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getColor() {
    return color;
  }

  public void setColor(String color) {
    this.color = color;
  }

  public String getSize() {
    return size;
  }

  public void setSize(String size) {
    this.size = size;
  }

  public boolean isAdmin() {
    return isAdmin;
  }

  public void setAdmin(boolean admin) {
    isAdmin = admin;
  }

  public int getRole() {
    return role;
  }

  public void setRole(int role) {
    this.role = role;
  }
}
