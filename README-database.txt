Install postgresql (INSTALL.txt) and configure as such:

# su - postgres
$ createuser -DRS -P blackhole
$ createdb blackhole -O blackhole
$ psql blackhole < /path/to/schema.sql

$ psql blackhole
psql (8.4.18)
Type "help" for help.

blackhole=# \dt
           List of relations
 Schema |    Name    | Type  |  Owner   
--------+------------+-------+----------
 public | blocklist  | table | blackhole
 public | blocklog   | table | blackhole
 public | unblocklog | table | blackhole
(3 rows)
