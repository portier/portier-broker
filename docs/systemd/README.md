# Portier Broker systemd units

This directory contains example [systemd] units for running the Portier broker
as a system service. Care has been taken to provide reasonably secure defaults.

[systemd]: https://systemd.io

To get started:

- Unpack the broker binaries in `/opt/portier-broker`. (If you'd like them
  elsewhere, modify `portier-broker.service`.)

- Prepare your configuration, either by creating `config.toml` in
  `/opt/portier-broker`, or by modifying `portier-broker.service` to provide
  configuration some other way.

- Place `portier-broker.service` in `/etc/systemd/system`.

- As root, run `systemctl daemon-reload` to reload the unit files.

- As root, run `systemctl start portier-broker.service` to start the service.
  Use `journalctl -u portier-broker` to inspect the broker log output.

- Verify the broker HTTP server is available.

- As root, run `systemctl enable portier-broker.service` to have systemd always
  start the service on system startup.

## Socket activation

The broker also supports [socket activation], which allows systemd to provide
the listening socket to the broker.

[socket activation]: http://0pointer.de/blog/projects/socket-activation.html

- Place `portier-broker.socket` in `/etc/systemd/system`, alongside
  `portier-broker.service`.

- As root, run `systemctl daemon-reload` to reload the unit files.

- As root, run `systemctl stop portier-broker.service` to stop any running
  broker service.

- As root, run `systemctl start portier-broker.socket` to have systemd create
  the socket.

- Verify the broker HTTP server is available. Systemd should start the broker
  on-demand, when the server is first accessed.

- As root, run `systemctl enable portier-broker.socket` to have systemd always
  create the socket on system startup.

- If desired, run `systemctl disable portier-broker.service` to have systemd
  always start the broker on-demand.
