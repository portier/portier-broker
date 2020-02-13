// Starts a broker with a minimal config.

const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");

const ROOT = path.resolve(__dirname, "../../../");
const BIN = path.resolve(ROOT, "target/debug/portier-broker");

module.exports = () => {
  const { privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048
  });
  const pem = privateKey.export({
    type: "pkcs8",
    format: "pem"
  });

  const subprocess = spawn(BIN, {
    stdio: "inherit",
    cwd: ROOT,
    env: {
      RUST_LOG: process.env.RUST_LOG || "error",
      RUST_BACKTRACE: "1",
      BROKER_PUBLIC_URL: "http://localhost:3333",
      BROKER_KEYTEXT: pem,
      BROKER_FROM_ADDRESS: "portier@example.com",
      BROKER_SMTP_SERVER: "localhost:1025",
      BROKER_LIMIT_PER_EMAIL: "10000/min"
    }
  });

  return {
    destroy() {
      subprocess.kill();
    }
  };
};
