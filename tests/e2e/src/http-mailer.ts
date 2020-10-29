import express from "express";
import bodyParser from "body-parser";
import { Mailbox } from "./mailbox";

export interface HttpMailerRequest {
  headers: { [key: string]: string | string[] | undefined };
  body: any;
}

export interface HttpMailer {
  destroy(): void;
  clearRequests(): void;
  getRequests(): HttpMailerRequest[];
}

const jsonParser = bodyParser.json();
const formParser = bodyParser.urlencoded({ extended: false });

export default ({ mailbox }: { mailbox: Mailbox }): HttpMailer => {
  const app = express();

  let requests: HttpMailerRequest[] = [];

  app.post("/postmark", jsonParser, (req, res) => {
    requests.push({ headers: req.headers, body: req.body });
    mailbox.pushMail(req.body.TextBody);
    return res.json({ ErrorCode: 0 });
  });

  app.post("/mailgun/:domain/messages", formParser, (req, res) => {
    requests.push({ headers: req.headers, body: req.body });
    mailbox.pushMail(req.body.text);
    return res.json({
      message: "Queued. Thank you.",
      id: "<20111114174239.25659.5817@samples.mailgun.org>",
    });
  });

  const server = app.listen(44920, "localhost");

  return {
    destroy() {
      server.close();
    },
    clearRequests() {
      requests = [];
    },
    getRequests() {
      return requests;
    },
  };
};
