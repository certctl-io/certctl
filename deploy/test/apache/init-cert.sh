#!/bin/sh
# Generate an initial known-good cert so Apache starts cleanly. The
# e2e tests rotate this via the connector.
set -e
mkdir -p /usr/local/apache2/conf/certs
if [ ! -f /usr/local/apache2/conf/certs/cert.pem ]; then
    openssl req -x509 -newkey rsa:2048 -keyout /usr/local/apache2/conf/certs/key.pem \
        -out /usr/local/apache2/conf/certs/cert.pem -days 1 -nodes \
        -subj "/CN=apache-test.local"
    cp /usr/local/apache2/conf/certs/cert.pem /usr/local/apache2/conf/certs/chain.pem
fi
