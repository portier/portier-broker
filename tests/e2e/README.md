# Portier broker end-to-end tests

This directory contains end-to-end tests for the Portier broker, written using
Node.js and Selenium WebDriver.

You must have a debug build ready of the broker. The tests expect to find it at
the cargo default path `target/debug/portier-broker`.

Tests will try to listen on the following ports (on localhost) for the duration
of the test run: 44125, 44133, 44180.

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
