// The main test suite.

const assert = require("assert");
const fetch = require("node-fetch");
const mailhog = require("./mailhog");
const { By, Key, until } = require("selenium-webdriver");

const ALL_TESTS = [];
const test = (name, fn) => ALL_TESTS.push({ name, fn });

const TIMEOUT = 5000;
const JOHN_EMAIL = "john.doe@example.com";
const BROKER_CONFIRM_TITLE = "Portier – Confirm your address";
const RP_CONFIRMED_TITLE = "RP: Confirmed";
const RP_GOT_ERROR_TITLE = "RP: Got error";

test("successful flow with code input", async ({ driver }) => {
  await driver.get("http://localhost:8000/");

  const emailInput = await driver.findElement(By.name("email"));
  await emailInput.sendKeys(JOHN_EMAIL, Key.RETURN);
  await driver.wait(until.titleIs(BROKER_CONFIRM_TITLE), TIMEOUT);

  const mail = await mailhog.fetchOne();
  const match = /^[a-z0-9]{6} [a-z0-9]{6}$/m.exec(mail);
  if (!match) {
    throw Error("Could not find the verification code in the email text");
  }
  const code = match[0];

  const codeInput = await driver.findElement(By.name("code"));
  await codeInput.sendKeys(code, Key.RETURN);
  await driver.wait(until.titleIs(RP_CONFIRMED_TITLE), TIMEOUT);

  const textElement = await driver.findElement(By.tagName("p"));
  const text = await textElement.getText();
  assert.equal(text, JOHN_EMAIL);
});

test("successful flow following the email link", async ({ driver }) => {
  await driver.get("http://localhost:8000/");

  const emailInput = await driver.findElement(By.name("email"));
  await emailInput.sendKeys(JOHN_EMAIL, Key.RETURN);
  await driver.wait(until.titleIs(BROKER_CONFIRM_TITLE), TIMEOUT);

  const mail = await mailhog.fetchOne();
  const match = /^http:\/\/localhost:3333\/confirm\?.+$/m.exec(mail);
  if (!match) {
    throw Error("Could not find the confirmation URL in the email text");
  }
  const url = match[0];

  await driver.get(url);
  await driver.wait(until.titleIs(RP_CONFIRMED_TITLE), TIMEOUT);

  const textElement = await driver.findElement(By.tagName("p"));
  const text = await textElement.getText();
  assert.equal(text, JOHN_EMAIL);
});

test("can omit email scope", async ({ driver, relyingParty }) => {
  let authUrl = await relyingParty.portier.authenticate(JOHN_EMAIL);
  authUrl = authUrl.replace(/scope=openid%20email/, "scope=openid");

  await driver.get(authUrl);
  await driver.wait(until.titleIs(BROKER_CONFIRM_TITLE), TIMEOUT);
});

test("cannot omit openid scope", async ({ driver, relyingParty }) => {
  let authUrl = await relyingParty.portier.authenticate(JOHN_EMAIL);
  authUrl = authUrl.replace(/scope=openid%20email/, "scope=email");

  relyingParty.on("gotError", body => {
    assert.equal(
      body.error_description,
      "unsupported scope, must contain 'openid' and optionally 'email'"
    );
  });
  await driver.get(authUrl);
  await driver.wait(until.titleIs(RP_GOT_ERROR_TITLE), TIMEOUT);
});

test("cannot add unknown scope", async ({ driver, relyingParty }) => {
  let authUrl = await relyingParty.portier.authenticate(JOHN_EMAIL);
  authUrl = authUrl.replace(/scope=openid%20email/, "scope=openid%20dummy");

  relyingParty.on("gotError", body => {
    assert.equal(
      body.error_description,
      "unsupported scope, must contain 'openid' and optionally 'email'"
    );
  });
  await driver.get(authUrl);
  await driver.wait(until.titleIs(RP_GOT_ERROR_TITLE), TIMEOUT);
});

module.exports = async ctx => {
  for (const { name, fn } of ALL_TESTS) {
    // Preparation.
    ctx.relyingParty.removeAllListeners();
    await mailhog.deleteAll();
    // Run test and apply a timeout.
    try {
      const timeout = new Promise((resolve, reject) =>
        setTimeout(() => {
          reject(Error("Test timed out"));
        }, TIMEOUT).unref()
      );
      await Promise.race([timeout, fn(ctx)]);
    } catch (err) {
      console.error(` ✖ ${name}`);
      console.error(err);
      process.exitCode = 1;
      continue;
    }
    console.error(` ✔ ${name}`);
  }
};
