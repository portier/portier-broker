#!/bin/sh

# A dummy sendmail executable for testing.

exec curl -fsS -X POST --data-binary @- http://localhost:44920/raw
