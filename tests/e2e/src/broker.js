// Starts a broker with a minimal config.

const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");

const {
  RUST_LOG = "error",
  TEST_REDIS,
  TEST_SQLITE,
  TEST_ROTATING_KEYS
} = process.env;

const ROOT = path.resolve(__dirname, "../../../");
const BIN = path.resolve(ROOT, "target/debug/portier-broker");

module.exports = () => {
  const env = {
    RUST_LOG: process.env.RUST_LOG || "error",
    RUST_BACKTRACE: "1",
    BROKER_PUBLIC_URL: "http://localhost:3333",
    BROKER_FROM_ADDRESS: "portier@example.com",
    BROKER_SMTP_SERVER: "localhost:1025",
    BROKER_LIMIT_PER_EMAIL: "10000/min"
  };

  if (TEST_REDIS) {
    env.BROKER_REDIS_URL = "redis://localhost/0";
  } else if (TEST_SQLITE) {
    const id = String(Math.random()).slice(2);
    env.BROKER_SQLITE_DB = `/tmp/portier-broker-test-${id}.sqlite3`;
  } else {
    env.BROKER_MEMORY_STORAGE = "true";
  }

  if (!TEST_ROTATING_KEYS) {
    const { privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048
    });
    env.BROKER_KEYTEXT = privateKey.export({
      type: "pkcs8",
      format: "pem"
    });
  }

  const subprocess = spawn(BIN, {
    stdio: "inherit",
    cwd: ROOT,
    env
  });

  return {
    destroy() {
      subprocess.kill();
    }
  };
};
