#!/bin/bash

source .venv/bin/activate
flask --app app init-db
flask --app app run --debug
