/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.StreamException;
import com.thoughtworks.xstream.security.ForbiddenClassException;
import org.junit.jupiter.api.Test;

public class VulnerableComponentsLessonTest {

  String strangeContact =
      "<contact class='dynamic-proxy'>\n"
          + "<interface>org.owasp.webgoat.vulnerablecomponents.Contact</interface>\n"
          + "  <handler class='java.beans.EventHandler'>\n"
          + "    <target class='java.lang.ProcessBuilder'>\n"
          + "      <command>\n"
          + "        <string>calc.exe</string>\n"
          + "      </command>\n"
          + "    </target>\n"
          + "    <action>start</action>\n"
          + "  </handler>\n"
          + "</contact>";
  String contact = "<contact>\n" + "</contact>";

  @Test
  public void testTransformation() throws Exception {
    XStream xstream = VulnerableComponentsLesson.createXStream();
    assertThat(xstream.fromXML(contact)).isInstanceOf(ContactImpl.class);
  }

  @Test
  public void testIllegalTransformation() throws Exception {
    XStream xstream = VulnerableComponentsLesson.createXStream();
    assertThrows(ForbiddenClassException.class, () -> xstream.fromXML(strangeContact));
  }

  @Test
  public void testIllegalPayload() throws Exception {
    XStream xstream = VulnerableComponentsLesson.createXStream();
    Exception e =
        assertThrows(
            StreamException.class, () -> ((Contact) xstream.fromXML("bullssjfs")).getFirstName());
    assertThat(e.getCause().getMessage().contains("START_DOCUMENT")).isTrue();
  }
}
