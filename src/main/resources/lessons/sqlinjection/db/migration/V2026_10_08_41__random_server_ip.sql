-- The production server's IP is the secret that assignment 12a asks for. A fixed, published value
-- (104.130.219.202) could simply be replayed, so every lesson schema gets its own random address.
UPDATE SERVERS
SET ip = '10.'
  || CAST(CAST(FLOOR(RAND() * 256) AS INTEGER) AS VARCHAR(3)) || '.'
  || CAST(CAST(FLOOR(RAND() * 256) AS INTEGER) AS VARCHAR(3)) || '.'
  || CAST(CAST(FLOOR(RAND() * 254) + 1 AS INTEGER) AS VARCHAR(3))
WHERE hostname = 'webgoat-prd';
