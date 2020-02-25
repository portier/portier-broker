# Portier Broker Redis storage

A [Redis] server can be used for storing all broker state. This is especially
useful for two scenario's:

- The filesystem is not reliable. This can be the case when the machine the
  broker runs on is provisioned, and can be recreated at any time. Cloud
  providers like Heroku do this, even if you only have one machine.

- You want to run multiple broker instances for scaling and/or redundancy.
  Redis storage supports this scenario, and coordinates across workers through
  special locks also kept in the Redis database.

To use Redis storage, set `redis_url` in your configuration, or
`BROKER_REDIS_URL` in the environment:

```toml
redis_url = "redis://my.redis.server/0"
```

For convenience, the broker will also pick up on the following environment
variables:

- `REDISTOGO_URL`
- `REDISGREEN_URL`
- `REDISCLOUD_URL`
- `REDIS_URL`
- `OPENREDIS_URL`

[Redis]: https://redis.io

## Security

It is strongly recommended to protect your Redis server at the network level.
You should take as much care as possible to only allow the broker to connect to
Redis. Ideally, you'd also ensure no eavesdropping is possible on the
connections (but this can be difficult in the cloud).

Notable DON'Ts:

- DO NOT rely on Redis password authentication. (The broker does support this,
  but it should only be used on top of other measures.)

- DO NOT share the Redis database with any other application.

- DO NOT share the Redis server with any other application by numbering
  databases. (ie. don't use `SELECT`)

## Eviction

Setting `maxmemory-policy` to one of the `volatile-*` options is recommended.
If you're unsure which, use `volatile-lru`.

Avoid the `allkeys-*` options, especially if you're using rotating signing
keys. Using these opens up the possibility that a malicious user floods your
server with data and causes the signing keys to be evicted.

It's also not recommended to use `noeviction`. The broker may not have a useful
way to handle errors for certain write operations to Redis, and it'll simply
exit in these cases.

## Snapshotting

Enabling snapshotting in Redis (using the `save` option) is, of course,
recommended. It'll allow Redis to recover the database across restarts.

You should take as much care as possible to ensure the snapshot location is
secure. The most basic measure to take here is to run Redis as its own user,
and to prevent other processes from reading the directory Redis saves snapshots
to using filesystem permissions.

Enabling `stop-writes-on-bgsave-error` is also recommended. This will cause the
broker to also hard-fail if your Redis server is not able to write snapshots,
which is usually what you want.

## Clustering and replication

The broker currently does not support clustered Redis installations, or
distributing load to read-only replicas.
