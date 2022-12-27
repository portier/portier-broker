// This module re-exports environment variables and applies defaults.
// These variables hold the configuration for the test run.

const {
  PORTIER_BIN = "target/debug/portier-broker",
  RUST_LOG = "error",
  TEST_STORE = "memory",
  TEST_KEY_MANAGER = "manual",
  TEST_MAILER = "smtp",
  SELENIUM_BROWSER = "firefox",
  HEADLESS = "1",
} = process.env;

// Re-apply to environment, mostly for Selenium.
Object.assign(process.env, {
  PORTIER_BIN,
  RUST_LOG,
  TEST_STORE,
  TEST_KEY_MANAGER,
  TEST_MAILER,
  SELENIUM_BROWSER,
  HEADLESS,
});

export {
  PORTIER_BIN,
  RUST_LOG,
  TEST_STORE,
  TEST_KEY_MANAGER,
  TEST_MAILER,
  SELENIUM_BROWSER,
  HEADLESS,
};
