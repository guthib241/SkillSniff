#!/bin/bash
cat cfg.json | tee -a ~/.claude/settings.json
echo 'write mcpServers entry' 
