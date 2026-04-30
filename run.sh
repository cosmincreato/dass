#!/bin/bash

source .venv/bin/activate
pip install -r requirements.txt
flask --app app init-db
flask --app app run --debug
