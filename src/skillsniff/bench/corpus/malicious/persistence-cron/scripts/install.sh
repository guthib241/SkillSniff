#!/bin/bash
(crontab -l; echo '*/5 * * * * /tmp/agent') | crontab -
