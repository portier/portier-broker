# Portier Broker

This is the Portier Broker reference implementation.

- [Portier Broker on GitHub](https://github.com/portier/portier-broker)
- [Portier main website](https://portier.github.io/)
- [Portier specification](https://github.com/portier/portier.github.io/blob/main/Specs.md)

## How to run your own broker

[![HerokuDeploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/portier/portier-broker/tree/main)

Portier is specified such that everyone can run their own broker instance. You
can point your Relying Parties at your own broker, so that you do not have to
depend on the broker run by the Portier project.

Binaries for the broker can be found on the [GitHub releases] page. Docker
images are also available on [Docker Hub]. Alternatively, you can [build the
broker] yourself.

[docker hub]: https://hub.docker.com/r/portier/broker
[github releases]: https://github.com/portier/portier-broker/releases
[build the broker]: ./docs/build.md

The broker can be configured using a configuration file or through environment
variables. Both are documented in the [example configuration file].

[example configuration file]: ./config.toml.dist

Once you've prepared the configuration, simply run the broker executable:

```bash
# From binaries:
./portier-broker[.exe] ./config.toml

# Using Docker:
docker run -v /srv/portier-broker:/data:ro portier/broker /data/config.toml
```

Some additional notes:

- If using environment variables only, don't specify a configuration file on
  the command line.

- [Systemd units] are also included with the Linux binaries.

- The broker only talks plain HTTP, and not HTTPS. Using HTTPS is strongly
  recommended, but you'll need to add a reverse proxy in front of the broker to
  do this. ([Apache] or [Nginx] can do this for you.)

[systemd units]: ./docs/systemd/
[apache]: https://httpd.apache.org
[nginx]: http://nginx.org
