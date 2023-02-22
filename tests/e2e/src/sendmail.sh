#!/bin/sh

# A dummy sendmail executable for testing.

exec curl -fsS -X POST --data-binary @- http://127.0.0.1:44920/raw
