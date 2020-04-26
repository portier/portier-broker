#!/usr/bin/env node

// Entry point for the test runner.

const runMailServer = require("./src/mailServer");
const runBroker = require("./src/broker");
const runRelyingParty = require("./src/relying-party");
const runTests = require("./src/tests");
const { Builder } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const firefox = require("selenium-webdriver/firefox");

const main = async () => {
  let mailServer, broker, relyingParty, driver;
  try {
    mailServer = runMailServer();
    broker = runBroker();
    relyingParty = runRelyingParty();
    driver = await createDriver();
    await runTests({ mailServer, broker, relyingParty, driver });
  } finally {
    if (driver) {
      await driver.quit().catch(err => {
        console.error("Error while stopping Selenium:");
        console.error(err);
      });
    }
    if (relyingParty) {
      relyingParty.destroy();
    }
    if (broker) {
      broker.destroy();
    }
    if (mailServer) {
      mailServer.destroy();
    }
  }
};

const createDriver = async browser => {
  const windowSize = { width: 800, height: 600 };
  const firefoxOptions = new firefox.Options().windowSize(windowSize);
  const chromeOptions = new chrome.Options().windowSize(windowSize);
  const { HEADLESS = "1" } = process.env;
  if (parseInt(HEADLESS, 10)) {
    firefoxOptions.headless();
    chromeOptions.headless();
  }

  const builder = new Builder();
  builder.setFirefoxOptions(firefoxOptions);
  builder.setChromeOptions(chromeOptions);
  if (!process.env.SELENIUM_BROWSER) {
    builder.forBrowser("firefox");
  }
  return builder.build();
};

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
