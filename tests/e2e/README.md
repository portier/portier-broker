# Portier broker end-to-end tests

This directory contains end-to-end tests for the Portier broker, written using
Node.js and Selenium WebDriver.

The tests look for the broker binary at `target/debug/portier-broker`, but this
can be overridden by setting `PORTIER_BIN`.

Tests will try to listen on the following ports (on localhost) for the duration
of the test run: 44125, 44133, 44180.

Install the test suite local dependencies with:

```bash
npm i
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
