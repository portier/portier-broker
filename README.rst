The Portier Broker reference implementation
===========================================

This is the reference implementation of the Broker side of the `Portier`_
protocol `specification`_. Feedback is welcome on `GitHub`_.

.. _Portier: https://portier.github.io/
.. _specification: protocol.md
.. _GitHub: https://github.com/portier/portier-broker


How to run your own broker
--------------------------

Portier is specified such that everyone can run their own Broker instance. You
can point your Relying Parties at your own broker, so that you do not have to
depend on the broker run by the Portier project.

Currently, this project does not ship any binaries. However, once you have the
Rust toolchain `installed`_, building portier broker is very simple:

.. code-block:: shell

   $ cargo install portier_broker

This should fetch and install the Portier broker. The binary is installed into
``~/.cargo/bin/`` by default. Running the `portier-broker` binary requires
a short configuration file. An example is provided in ``config.toml.dist``.

To run the broker, invoke it with the path to a configuration file:

.. code-block:: shell

   $ portier-broker config.toml

You can also supply all required settings as environment variables and
completely omit the configuration file.

You will also need a Redis server and an outgoing SMTP server.

.. _installed: https://doc.rust-lang.org/book/getting-started.html

Configuration
-------------

See ``config.toml.dist`` for an example configuration file. This file includes
reasonable default values for most settings, but you must explicitly set:

* ``server.public_url``: The server's public-facing URL.
* ``crypto.keyfiles``: An array of paths to encryption keys, or
* ``crypto.keytext``: The text of an encryption key in PEM format (takes precedence over keyfiles).
* ``redis.url``: The URL of a Redis server for temporary session storage.
* ``smtp.from_address``: The email address that outgoing mail is from.
* ``smtp.server``: The host and port of the outgoing mail server.

If necessary, set ``smtp.username`` and ``smtp.password`` to your SMTP server's
username and password.

To support in-browser Google Authentication for Gmail users, you must also
specify:

* ``google.client_id``: Your Google OAuth API Client ID

You can create encryption keys with ``openssl genrsa 4096 > private.pem``

The complete list of available values are:

**[server] section:**

=============== ====================== =====================
``config.toml`` Environment Variable   Default
=============== ====================== =====================
listen_ip       BROKER_IP              "127.0.0.1"
listen_port     BROKER_PORT            3333
public_url      BROKER_PUBLIC_URL      (none)
allowed_origins BROKER_ALLOWED_ORIGINS (none (unrestricted))
=============== ====================== =====================

**[headers] section:**

=============== ==================== ================
``config.toml`` Environment Variable Default
=============== ==================== ================
static_ttl      BROKER_STATIC_TTL    604800 (1 week)
discovery_ttl   BROKER_DISCOVERY_TTL 604800 (1 week)
keys_ttl        BROKER_KEYS_TTL      86400 (1 day)
=============== ==================== ================

**[crypto] section:**

=============== ==================== ================
``config.toml`` Environment Variable Default
=============== ==================== ================
token_ttl       BROKER_TOKEN_TTL     600 (10 minutes)
keyfiles        BROKER_KEYFILES      [] (empty array)
keytext         BROKER_KEYTEXT       (none)
=============== ==================== ================

**[redis] section:**

=============== ==================== ================
``config.toml`` Environment Variable Default
=============== ==================== ================
url             BROKER_REDIS_URL     (none) (example: redis://localhost:6379)
session_ttl     BROKER_SESSION_TTL   900 (15 minutes)
cache_ttl       BROKER_CACHE_TTL     3600 (1 hour)
=============== ==================== ================

**[smtp] section:**

=============== ==================== =========
``config.toml`` Environment Variable Default
=============== ==================== =========
from_name       BROKER_FROM_NAME     "Portier"
from_address    BROKER_FROM_ADDRESS  (none)
server          BROKER_SMTP_SERVER   (none)
username        BROKER_SMTP_USERNAME (none)
password        BROKER_SMTP_PASSWORD (none)
=============== ==================== =========

**[limit] section:**

=============== ====================== =======
``config.toml`` Environment Variable   Default
=============== ====================== =======
per_email       BROKER_LIMIT_PER_EMAIL "5/min"
=============== ====================== =======

**[google] section:**

=============== ======================= =======
``config.toml`` Environment Variable    Default
=============== ======================= =======
client_id       BROKER_GOOGLE_CLIENT_ID (none)
=============== ======================= =======

**[domain_overrides] section:**

This section contains arbitrary domain names, mapped to a list of
WebFinger-like links, allowing local configuration on the broker to skip and
override WebFinger queries for some domains.

This is currently most useful for G Suite domains that don't respond to
WebFinger, which can be specified as:

.. code-block:: toml

   [[domain_overrides."my-apps-domain.example"]]
   rel = "https://portier.io/specs/auth/1.0/idp/google"
   href = "https://accounts.google.com"

When the ``[google]`` section is present, default overrides are added for
``gmail.com`` and ``googlemail.com``.

Contributing
------------

If you want to hack on the broker code, clone this repository. If you have the
Rust toolchain installed (see above), you can run ``cargo build`` to build the
project in debug mode. ``cargo run -- <config-file>`` will run the project. You
will have to set up your own configuration file; use ``config.toml.dist`` as a
template.

The broker binds to ``127.0.0.1:3333`` by default. It only speaks HTTP, so you
must run it behind a reverse proxy like nginx to expose it to the web via TLS.
Note that the broker will serve up files from the ``.well-known`` directory
in the current working directory when executed; this makes it relatively easy
to request a certificate from `Let's Encrypt`_.

If you want to test a custom identity provider, you may want to do so locally
over plain HTTP, without TLS. This can be enabled with a compile-time flag as
follows: ``cargo run --features insecure -- <config-file>``. With this flag,
WebFinger queries are sent over plain HTTP, and plain HTTP links in the
WebFinger response are allowed.

If you want to test support for well-known identity providers, you will need
to configure them. For Google, you can request credentials through their
`API Manager`_.

It is not necessary to run your own email server for testing. Instead, use
`MailCatcher`_ or `MailHog`_ to get a dummy SMTP interface. The relevant part
of configuration to use MailCatcher with default settings can look like this:

.. code-block:: shell

   [smtp]
   # Display name for confirmation emails - Default: "Portier"
   from_name = "Portier"
   # Sender address for confirmation emails - Default: (none)
   from_address = "test@example.com"
   # Outgoing mailserver address - Default: (none)
   server = "127.0.0.1:1025"

To test your changes, you will need to set up a Relying Party; so far, the
Python `demo-rp` code has been used. This is a very bare-bones implementation
that only serves to prove authentication to the broker.

.. _demo-rp: https://github.com/portier/demo-rp
.. _Let's Encrypt: https://letsencrypt.org/
.. _API Manager: https://console.developers.google.com/apis/credentials
.. _MailCatcher: https://mailcatcher.me/
.. _MailHog: https://github.com/mailhog/MailHog
