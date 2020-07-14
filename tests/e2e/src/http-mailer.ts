import express from "express";
import bodyParser from "body-parser";

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

export default (): HttpMailer => {
  const app = express();

  let requests: HttpMailerRequest[] = [];

  app.post("/postmark", jsonParser, (req, res) => {
    requests.push({ headers: req.headers, body: req.body });
    return res.json({ ErrorCode: 0 });
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
