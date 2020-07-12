#!/usr/bin/env node

// Entry point for the test runner.

import { Builder, WebDriver } from "selenium-webdriver";
import chrome from "selenium-webdriver/chrome";
import firefox from "selenium-webdriver/firefox";

import createMailbox, { Mailbox } from "./src/mailbox";
import createBroker, { Broker } from "./src/broker";
import createRelyingParty, { RelyingParty } from "./src/relying-party";
import createTests from "./src/tests";

import { HEADLESS } from "./src/env";

const main = async () => {
  let mailbox: Mailbox | undefined,
    broker: Broker | undefined,
    relyingParty: RelyingParty | undefined,
    driver: WebDriver | undefined;
  try {
    mailbox = createMailbox();
    broker = createBroker({ mailbox });
    relyingParty = createRelyingParty();
    driver = await createDriver();
    await createTests({ mailbox, broker, relyingParty, driver });
  } finally {
    if (driver) {
      await driver.quit().catch((err) => {
        console.error("Error while stopping Selenium:");
        console.error(err);
      });
    }
    if (relyingParty) {
      relyingParty.destroy!();
    }
    if (broker) {
      broker.destroy();
    }
    if (mailbox) {
      mailbox.destroy();
    }
  }
};

const createDriver = async () => {
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

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
