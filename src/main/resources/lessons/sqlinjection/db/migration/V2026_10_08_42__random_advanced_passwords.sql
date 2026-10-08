-- Dave's password (assignment 6b) and Tom's password (blind injection challenge) were fixed,
-- published values that could simply be replayed. Every lesson schema now gets its own random
-- passwords, so they can only be learned through the (now closed) injection flaws.
UPDATE user_system_data
SET password = 'd' || CAST(CAST(FLOOR(RAND() * 1000000000) AS BIGINT) AS VARCHAR(9))
WHERE user_name = 'dave';

UPDATE sql_challenge_users
SET password = 't'
  || CAST(CAST(FLOOR(RAND() * 1000000000) AS BIGINT) AS VARCHAR(9))
  || CAST(CAST(FLOOR(RAND() * 1000000000) AS BIGINT) AS VARCHAR(9))
WHERE userid = 'tom';
