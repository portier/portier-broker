// Starts a simple relying party implementation.

const express = require("express");
const formParser = require("body-parser").urlencoded({ extended: false });
const { PortierClient } = require("portier");

module.exports = () => {
  const portier = new PortierClient({
    broker: "http://localhost:3333",
    redirectUri: "http://localhost:8000/verify"
  });

  const app = express();

  app.get("/", (req, res) => {
    res.type("html").end(`
      <title>Login</title>
      <form method="post" action="/auth">
        <input name="email" type="email">
      </form>
    `);
  });

  app.post("/auth", formParser, async (req, res) => {
    let authUrl;
    try {
      authUrl = await portier.authenticate(req.body.email);
    } catch (err) {
      console.error("RP failed to start authentication:");
      console.error(err);
      return res.status(500).end();
    }

    res.redirect(303, authUrl);
  });

  app.post("/verify", formParser, async (req, res) => {
    if (req.body.error) {
      console.error(`Broker returned to RP with error: ${req.body.error}`);
      console.error(`Description: ${req.body.error_description}`);
      return res.status(500).end();
    }

    let email;
    try {
      email = await portier.verify(req.body.id_token);
    } catch (err) {
      console.error("RP failed to verify token:");
      console.error(err);
      return res.status(500).end();
    }

    res.type("html").end(`
      <title>Confirmed</title>
      <p>Verified email address ${email}!</p>
    `);
  });

  const server = app.listen(8000);

  return {
    destroy() {
      server.close();
      portier.destroy();
    }
  };
};
