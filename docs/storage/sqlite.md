# Portier Broker SQLite storage

An [SQLite] database can be used for storing all broker state. This is the
recommended option for simple installations on a single server, that don't need
to service large numbers of users or provide high availability.

To use Redis storage, set `sqlite_db` in your configuration, or
`BROKER_SQLITE_DB` in the environment:

```toml
sqlite_db = "/var/lib/portier-broker/db.sqlite3"
```

[SQLite]: https://www.sqlite.org/index.html

## Security

You should take as much care as possible to ensure the database location is
secure. The most basic measure to take here is to run the broker as its own
user, and to prevent other processes from reading the directory containing the
database using filesystem permissions.

## Database sharing

The broker currently does not support sharing the database across multiple
instances. It expects to be the only one accessing the database file, and does
not put any special effort into synchronizing with other processes beyond the
default SQLite file locking.

## Networked filesystems

DO NOT use SQLite storage on a networked filesystem. SQLite specifically
recommends against this: https://www.sqlite.org/faq.html#q5
