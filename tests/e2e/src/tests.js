// The main test suite.

const assert = require("assert");
const mailhog = require("./mailhog");
const { By, Key, until } = require("selenium-webdriver");

const ALL_TESTS = [];
const test = (name, fn) => ALL_TESTS.push({ name, fn });

test("successful flow with code input", async driver => {
  await driver.get("http://localhost:8000/");

  const emailInput = await driver.findElement(By.name("email"));
  await emailInput.sendKeys("john.doe@example.com", Key.RETURN);
  await driver.wait(until.titleIs("Portier – Confirm your address"), 10000);

  const mail = await mailhog.fetchOne();
  const match = /^[a-z0-9]{6} [a-z0-9]{6}$/m.exec(mail);
  if (!match) {
    throw Error("Could not find the verification code in the email text");
  }
  const code = match[0];

  const codeInput = await driver.findElement(By.name("code"));
  await codeInput.sendKeys(code, Key.RETURN);
  await driver.wait(until.titleIs("Confirmed"), 10000);

  const textElement = await driver.findElement(By.tagName("p"));
  const text = await textElement.getText();
  assert.equal(text, "Verified email address john.doe@example.com!");
});

test("successful flow following the email link", async driver => {
  await driver.get("http://localhost:8000/");

  const emailInput = await driver.findElement(By.name("email"));
  await emailInput.sendKeys("john.doe@example.com", Key.RETURN);
  await driver.wait(until.titleIs("Portier – Confirm your address"), 10000);

  const mail = await mailhog.fetchOne();
  const match = /^http:\/\/localhost:3333\/confirm\?.+$/m.exec(mail);
  if (!match) {
    throw Error("Could not find the confirmation URL in the email text");
  }
  const url = match[0];

  await driver.get(url);

  const textElement = await driver.findElement(By.tagName("p"));
  const text = await textElement.getText();
  assert.equal(text, "Verified email address john.doe@example.com!");

  // Ensure the link no longer works.
  await driver.get(url);

  const introElement = await driver.findElement(By.className("head"));
  const intro = await introElement.getText();
  assert.equal(intro, "The session has expired.");
});

module.exports = async driver => {
  for (const { name, fn } of ALL_TESTS) {
    await mailhog.deleteAll();
    try {
      await fn(driver);
    } catch (err) {
      console.error(` ✖ ${name}`);
      console.error(err);
      process.exitCode = 1;
      continue;
    }
    console.error(` ✔ ${name}`);
  }
};
