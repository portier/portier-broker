// Handles the mailbox for testing.
import { SMTPServer } from "smtp-server";
import { simpleParser } from "mailparser";
import { TEST_MAILER } from "./env";
import type { Stream } from "stream";

const parseOptions = {
  skipHtmlToText: true,
  skipTextToHtml: true,
};

export interface Mailbox {
  pushRawMail(
    input: string | Stream,
    callback?: (err?: Error | undefined) => void
  ): void;
  pushMail(mail: string): void;
  nextMail(): string | undefined;
  clearMail(): void;
  destroy(): void;
}

export default (): Mailbox => {
  // SMTP server instance, created when testing SMTP only.
  let server: SMTPServer | undefined;
  // Contains text bodies of mails received.
  const mails: string[] = [];

  // Exported API.
  const api: Mailbox = {
    pushRawMail(
      input: string | Stream,
      callback?: (err?: Error) => void
    ): void {
      simpleParser(input, parseOptions as any, (err, parsed) => {
        if (!err) {
          api.pushMail(parsed.text ?? "");
        }
        if (callback) {
          callback(err);
        } else if (err) {
          console.error(err);
        }
      });
    },
    pushMail(mail: string) {
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
    },
  };

  // Start the SMTP server if needed.
  if (TEST_MAILER === "smtp") {
    server = new SMTPServer({
      hideSTARTTLS: true,
      disableReverseLookup: true,
      disabledCommands: ["AUTH"],
      onData(stream, _session, callback) {
        api.pushRawMail(stream, callback);
      },
    });
    server.listen(44125, "localhost");
  }

  return api;
};
