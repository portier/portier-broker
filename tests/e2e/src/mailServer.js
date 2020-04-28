// Starts a simple SMTP server for testing.

const { SMTPServer } = require("smtp-server");
const { simpleParser } = require("mailparser");

const parseOptions = {
  skipHtmlToText: true,
  skipTextToHtml: true
};

module.exports = () => {
  const mails = [];

  const server = new SMTPServer({
    hideSTARTTLS: true,
    disableReverseLookup: true,
    disabledCommands: ["AUTH"],

    onData(stream, session, callback) {
      simpleParser(stream, parseOptions, (err, parsed) => {
        if (!err) {
          mails.push(parsed.text);
        }
        callback(err);
      });
      stream.on("end", callback);
    }
  });

  server.listen(44125, "localhost");

  return {
    nextMail() {
      return mails.shift();
    },
    clearMail() {
      mails.length = 0;
    },
    destroy() {
      server.close();
    }
  };
};
