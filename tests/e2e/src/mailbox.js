// Handles the mailbox for testing.

const { SMTPServer } = require("smtp-server");
const { simpleParser } = require("mailparser");

const parseOptions = {
  skipHtmlToText: true,
  skipTextToHtml: true
};

const { TEST_MAILER } = require("./env");

module.exports = () => {
  // SMTP server instance, created when testing SMTP only.
  let server;
  // Contains text bodies of mails received.
  const mails = [];

  // Exported API.
  const api = {
    pushRawMail(input, callback) {
      simpleParser(input, parseOptions, (err, parsed) => {
        if (!err) {
          api.pushMail(parsed.text);
        }
        if (callback) {
          callback(err);
        } else if (err) {
          console.error(err);
        }
      });
    },
    pushMail(mail) {
      mails.push(mail);
    },
    nextMail() {
      return mails.shift();
    },
    clearMail() {
      mails.length = 0;
    },
    destroy() {
      if (server) {
        server.close();
        server = undefined;
      }
    }
  };

  // Start the SMTP server if needed.
  if (TEST_MAILER === "smtp") {
    server = new SMTPServer({
      hideSTARTTLS: true,
      disableReverseLookup: true,
      disabledCommands: ["AUTH"],
      onData(stream, session, callback) {
        api.pushRawMail(stream, callback);
      }
    });
    server.listen(44125, "localhost");
  }

  return api;
};
