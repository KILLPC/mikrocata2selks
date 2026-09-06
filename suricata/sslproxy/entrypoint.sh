#!/bin/bash

# 1. Start SSLproxy in the foreground
exec /usr/bin/sslproxy -f /etc/sslproxy/sslproxy.conf
