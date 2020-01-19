// Utilities for talking to Mailhog.

const assert = require("assert");
const fetch = require("node-fetch");

exports.deleteAll = async () => {
  const response = await fetch("http://localhost:8025/api/v1/messages", {
    method: "DELETE"
  });
  if (response.status !== 200) {
    throw Error(`Unexpected status deleting mail: ${response.status}`);
  }
};

exports.fetchOne = async () => {
  const response = await fetch("http://localhost:8025/api/v2/messages");
  if (response.status !== 200) {
    throw Error(`Unexpected status fetching mail: ${response.status}`);
  }

  await exports.deleteAll();

  const { items } = await response.json();
  assert.equal(items.length, 1, "Expected 1 mail in our inbox");

  return findTextPart(items[0].MIME.Parts).Body;
};

const findTextPart = mimeParts => {
  const textPart = mimeParts.find(part =>
    (part.Headers["Content-Type"] || []).some(
      value => value.indexOf("text/plain") === 0
    )
  );
  if (textPart) {
    return textPart;
  }

  const nestedPart = mimeParts.find(part =>
    (part.Headers["Content-Type"] || []).some(
      value => value.indexOf("multipart/") === 0
    )
  );
  if (nestedPart) {
    return findTextPart(nestedPart.MIME.Parts);
  }

  throw Error("Could not find plain text part in mail");
};
