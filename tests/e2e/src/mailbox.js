// Handles the mailbox for testing.

const { SMTPServer } = require("smtp-server");
const { simpleParser } = require("mailparser");

const parseOptions = {
  skipHtmlToText: true,
  skipTextToHtml: true
};

const { TEST_MAILER } = require("./env");

module.exports = () => {
  let server;
  const mails = [];

  const api = {
    pushRawMail(input, callback) {
      simpleParser(input, parseOptions, (err, parsed) => {
        if (!err) {
          mails.push(parsed.text);
        }
        if (callback) {
          callback(err);
        } else if (err) {
          console.error(err);
        }
      });
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
