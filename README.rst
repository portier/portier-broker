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

You will also need a Redis server and an outgoing SMTP server.

.. _installed: https://doc.rust-lang.org/book/getting-started.html


Configuration
-------------

See ``config.toml.dist`` for an example configuration file. The example file
includes reasonable default values for most settings, but you must explicitly
set:

* ``server.public_url``: The server's public-facing URL.
* ``crypto.keyfiles``: An array of paths to encryption keys (create keys with
  ``openssl genrsa 4096 > private.pem``).
* ``redis.url``: The URL of a Redis server for temporary session storage.
* ``smtp.from_address``: The email address that outgoing mail is from.
* ``smtp.server``: The host and port of the outgoing mail server.

To support in-browser Google Authentication for Gmail users, you must also
specify:

* ``providers."gmail.com".client_id``: Your Google OAuth API Client ID
* ``providers."gmail.com".secret``: Your Google OAuth API Secret Key

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
