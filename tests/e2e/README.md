# Portier broker end-to-end tests

This directory contains end-to-end tests for the Portier broker, written using
Node.js and Selenium WebDriver.

To run the tests, you'll need to have a Mailhog instance running and reachable
at `localhost:1025` for SMTP and `localhost:8025` for the API.

You must also have a debug build ready of the broker. The tests expect to find
it at the cargo default path `target/debug/portier-broker`. The tests will
automatically start and stop the broker, listening on `localhost:3333`.

The tests also automatically start and stop a small server with a relying
party, listening on `localhost:8000`. The code for this is included in the
tests.

Install the test suite local dependencies with:

```bash
yarn
```

Run the test suite with:

```bash
SELENIUM_BROWSER=firefox ./main.js
```

If no browser is set, tests will try to start Firefox by default. Whichever
browser you choose, you must have the correct WebDriver installed for that
browser. (E.g. `geckodriver` for Firefox.)

For Firefox and Chrome, tests will attempt to run headless by default. To
disable this behavior, also set `HEADLESS=0`.
