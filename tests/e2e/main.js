#!/usr/bin/env node

// Entry point for the test runner.

const { Builder } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const firefox = require("selenium-webdriver/firefox");

const createMailbox = require("./src/mailbox");
const createBroker = require("./src/broker");
const createRelyingParty = require("./src/relying-party");
const createTests = require("./src/tests");

const { HEADLESS } = require("./src/env");

const main = async () => {
  let mailbox, broker, relyingParty, driver;
  try {
    mailbox = createMailbox();
    broker = createBroker({ mailbox });
    relyingParty = createRelyingParty();
    driver = await createDriver();
    await createTests({ mailbox, broker, relyingParty, driver });
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
    if (mailbox) {
      mailbox.destroy();
    }
  }
};

const createDriver = async browser => {
  const windowSize = { width: 800, height: 600 };
  const firefoxOptions = new firefox.Options().windowSize(windowSize);
  const chromeOptions = new chrome.Options().windowSize(windowSize);
  if (HEADLESS === "1") {
    firefoxOptions.headless();
    chromeOptions.headless();
  }

  const builder = new Builder();
  builder.setFirefoxOptions(firefoxOptions);
  builder.setChromeOptions(chromeOptions);
  return builder.build();
};

main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
