#!/bin/bash

TLS_DIR='/root/nginx/tls'
APP_DIR='/home/usr/app'

mv "${TLS_DIR}"/crl.pem "${TLS_DIR}"/crl.pem.backup;
cp "${APP_DIR}"/crl.pem "${TLS_DIR}"/crl.pem;
sudo nginx -t;
if [ $? -eq 0 ]; then
	systemctl reload nginx;
	rm "${TLS_DIR}"/crl.pem.backup;
else
	rm "${TLS_DIR}"/crl.pem;
	mv "${TLS_DIR}"/crl.pem.backup "${TLS_DIR}"/crl.pem;
fi

