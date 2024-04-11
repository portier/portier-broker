import express from "express";
import { Mailbox } from "./mailbox";
import {
  json as createJsonParser,
  urlencoded as createFormParser,
} from "body-parser";

export interface HttpMailerRequest {
  headers: { [key: string]: string | string[] | undefined };
  body: any;
}

export interface HttpMailer {
  destroy(): void;
  clearRequests(): void;
  getRequests(): HttpMailerRequest[];
}

const jsonParser = createJsonParser();
const formParser = createFormParser({ extended: false });

export default ({ mailbox }: { mailbox: Mailbox }): HttpMailer => {
  const app = express();

  let requests: HttpMailerRequest[] = [];

  app.post("/raw", (req, res) => {
    mailbox.pushRawMail(req);
    return res.status(204).end();
  });

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

  app.post("/sendgrid", jsonParser, (req, res) => {
    requests.push({ headers: req.headers, body: req.body });
    mailbox.pushMail(req.body.content[1].value);
    return res.status(202).end();
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
