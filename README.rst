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

.. _installed: https://doc.rust-lang.org/book/getting-started.html


Configuration
-------------

Here's an example configuration file:

.. code-block:: toml

    listen_ip = "127.0.0.1"
    listen_port = 3333
    base_url = "https://portier.example.com"
    token_validity = 600

    [[keys]]
    file = "private.pem"

    [store]
    redis_url = "redis://127.0.0.1/5"
    expire_sessions = 900
    expire_cache = 3600
    max_response_size = 8096

    [smtp]
    address = "localhost:25"

    [sender]
    name = "Portier"
    address = "portier@example.com"

    [providers . "gmail.com"]
    discovery = "https://accounts.google.com/.well-known/openid-configuration"
    client_id = "1234567890-example-client-id.apps.googleusercontent.com"
    secret = "<your-secret-goes-here>"
    issuer = "accounts.google.com"

**listen_ip** and **listen_port** contain the port on which the broker listens.

**base_url** contains the web origin for this broker instance.

**token_validity** is a value in seconds, that determines how long outgoing
authentication tokens are allowed to live. Defaults to 600s, or 10 minutes.

**keys** is a list of RSA private keys, with a ``file`` path for each key.
Multiple keys can be used to implement key rotation. By default, the last key
in the list will be used for signing the outgoing JWTs.

**store** has a ``redis_url`` value that points to a Redis database. This is
used for ephemeral state, most importantly for tracking login attempts while
waiting for authorization from the user, and caching of identity provider
configuration. The broker itself is stateless. ``expire_sessions`` contains the
lifetime (in seconds) for sessions kept during login attempts. In the example,
login attempts are timed out after 900s, or 15 minutes. ``expire_cache``
contains the minimum lifetime (in seconds) for the cache entries, but
individual entries may be kept longer if this is indicated in the HTTP headers
providers send. ``max_response_size`` is the maximum allowed size (in bytes) of
configuration documents from identity providers.

**smtp** contains SMTP client settings, currently just the ``address``, which
should be in the format ``<host>:<port>``.

**sender** is the sender information used when sending email for the email
loop authentication. It requires ``name`` and ``address`` keys.

**providers** is an object containing well-known Identity Providers, for
which an account is required to authenticate. Keys in this object represent
an email address domain name for which this IdP will be used. The value is
another object, which contains four more key-value pairs:

* ``discovery``: the `OpenID Provider Configuration Document URL`_ for the
  provider
* ``client_id``: the client ID for the broker registration with the IdP
* ``secret``: the secret for this broker's registration with the IdP
* ``issuer``: the expected issuer for identity tokens received from this IdP

.. _OpenID Provider Configuration Document URL: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig


Contributing
------------

If you want to hack on the broker code, clone this repository. If you have the
Rust toolchain installed (see above), you can run ``cargo build`` to build the
project in debug mode. ``cargo run <config-file>`` will run the project. You
will have to set up your own configuration file; use ``config.toml.dist``
as a template.

The broker binds to ``127.0.0.1:3333`` by default. It only speaks HTTP, so you
must run it behind a reverse proxy like nginx to expose it to the web via TLS.
Note that the broker will serve up files from the ``.well-known`` directory
in the current working directory when executed; this makes it relatively easy
to request a certificate from `Let's Encrypt`_.

If you want to test support for well-known identity providers, you will need
to configure them. For Google, you can request credentials through their
`API Manager`_.

To test your changes, you will need to set up a Relying Party; so far, the
Python `demo-rp` code has been used. This is a very bare-bones implementation
that only serves to prove authentication to the broker.

.. _demo-rp: https://github.com/portier/demo-rp
.. _Let's Encrypt: https://letsencrypt.org/
.. _API Manager: https://console.developers.google.com/apis/credentials
