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
a short configuration file, an example of which is provided as ``test.json``.
You may also want to refer to the output of ``portier-broker --help``.

.. _installed: https://doc.rust-lang.org/book/getting-started.html


Portier broker configuration
----------------------------

Here's an example configuration file:

.. code-block:: json

   {
     "base_url": "https://portier.example.com",
     "keys": [
       {"id": "base", "file": "private.pem"}
     ],
     "store": {
       "redis_url": "redis://127.0.0.1/5",
       "expire_keys": 900
     },
     "sender": {
       "name": "Portier",
       "address": "portier@example.com"
     },
     "token_validity": 600,
     "providers": {
       "gmail.com": {
         "discovery": "https://accounts.google.com/.well-known/openid-configuration",
         "client_id": "1234567890-example-client-id.apps.googleusercontent.com",
         "secret": "<your-secret-goes-here>",
         "issuer": "accounts.google.com"
       }
     }
   }

**base_url** contains the web origin for this broker instance.

**key** is a list of keys, with an ``id`` and ``file`` for each key.
Multiple keys can be used to implement key rotation. By default, the last key
in the list will be used for signing the outgoing JWTs.

**store** has a ``redis_url`` value that points to a Redis database. This
is used for ephemeral state, most importantly for tracking login attempts
while waiting for authorization from the user. The broker itself is stateless.
``expire_keys`` contains the lifetime (in seconds) for such data. In the
example, login attempts are timed out after 900s, or 15 minutes.

**sender** is the sender information used when sending email for the email
loop authentication. It requires ``name`` and ``address`` keys.

**token_validity** is a value in seconds, that determines how long outgoing
authentication tokens are allowed to live. Defaults to 600s, or 10 minutes.

**providers** is an object containing well-known Identity Providers, for
which an account is required to authenticate.
