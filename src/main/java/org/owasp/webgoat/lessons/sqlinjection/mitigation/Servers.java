/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 6/13/17.
 */
@RestController
@RequestMapping("SqlInjectionMitigations/servers")
@Slf4j
public class Servers {

  private final LessonDataSource dataSource;

  @AllArgsConstructor
  @Getter
  private class Server {

    private String id;
    private String hostname;
    private String ip;
    private String mac;
    private String status;
    private String description;
  }

  // ORDER BY cannot take a bind parameter, so the column is checked against an allow-list
  private static final Set<String> SORTABLE_COLUMNS =
      Set.of("id", "hostname", "ip", "mac", "status", "description");

  public Servers(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public List<Server> sort(@RequestParam String column) throws Exception {
    List<Server> servers = new ArrayList<>();
    String sortColumn =
        column != null && SORTABLE_COLUMNS.contains(column.toLowerCase(Locale.ROOT))
            ? column.toLowerCase(Locale.ROOT)
            : "id";

    try (var connection = dataSource.getConnection()) {
      try (var statement =
          connection.prepareStatement(
              "select id, hostname, ip, mac, status, description from SERVERS where status <> 'out"
                  + " of order' order by "
                  + sortColumn)) {
        try (var rs = statement.executeQuery()) {
          while (rs.next()) {
            Server server =
                new Server(
                    rs.getString(1),
                    rs.getString(2),
                    rs.getString(3),
                    rs.getString(4),
                    rs.getString(5),
                    rs.getString(6));
            servers.add(server);
          }
        }
      }
    }
    return servers;
  }
}
