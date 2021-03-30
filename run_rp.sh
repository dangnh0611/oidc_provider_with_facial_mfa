#! /usr/bin/bash

source venv/bin/activate
# bypass CA
export CURL_CA_BUNDLE=""

# python3 app.py 3000
python3 relying_party/app.py $1