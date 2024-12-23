#!/bin/bash

#
# Reference:
# https://blog.niklasottosson.com/misc/how-to-check-a-certificate-chain-in-a-jks/
# keytool -list -v -keystore [jks name]
# 
# https://www.ssl247.com/knowledge-base/detail/how-do-i-verify-that-a-private-key-matches-a-certificate-openssl-1527076112539/ka03l0000015hscaay/
# openssl rsa -check -noout -in [key file]
# 
# https://www.warp.dev/terminus/openssl-check-certificate
# openssl x509 -noout -enddate -in [cert]
# 

HOSTNAME="localhost"
CREDS_FILE="ssl_cert.creds"

DAYS="3650"
CREDS_VAL="kafkapwd"
COUNTRY="HK"
STATE="HK"
LOCALITY="Hong\ Kong"

ORG_CA="CA\ Root\ 01"
OU_CA="CA_ROOT_01"
ORG_CERT="Cert\ 01"
OU_CERT="CERT_01"

SUBJ_CA="/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORG_CA}/OU=${OU_CA}"
SUBJ_CERT="/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORG_CERT}/OU=${OU_CERT}"
DNAME_CA="CN=${CN_CA}, OU=${OU_CA}, O=${ORG_CA}, L=${LOCALITY}, S=${STATE}, C=${COUNTRY}"


#echo "${CREDS_VAL}"
#echo "${SUBJ_CA}"
#echo "${SUBJ_CERT}"

#Step 1
#keytool -keystore server.keystore.jks -alias localhost -validity 3650 -keyalg RSA -genkey
keytool -keystore server.keystore.jks -alias "${HOSTNAME}" -validity "${DAYS}" -keyalg RSA -genkey -dname "${DNAME_CA}" -storepass "${CREDS_VAL}" -keypass "${CREDS_VAL}"

#Step 2
#openssl req -new -x509 -keyout ca-key -out ca-cert -days 3650 -subj '/C=HK/ST=HK/L=Hong\ Kong/O=CA\ Root\ 01/OU=CA_ROOT_01'
openssl req -new -x509 -keyout ca-key -out ca-cert -days "${DAYS}" -subj "${SUBJ_CA}" -passin pass:"${CREDS_VAL}" -passout pass:"${CREDS_VAL}"
#keytool -keystore server.truststore.jks -alias CARoot -import -file ca-cert
keytool -keystore server.truststore.jks -alias CARoot -import -file ca-cert -dname "${DNAME_CA}" -storepass "${CREDS_VAL}" -noprompt
#keytool -keystore client.truststore.jks -alias CARoot -import -file ca-cert
keytool -keystore client.truststore.jks -alias CARoot -import -file ca-cert -dname "${DNAME_CA}" -storepass "${CREDS_VAL}" -noprompt

#Step 3
#keytool -keystore server.keystore.jks -alias localhost -certreq -file cert-file
keytool -keystore server.keystore.jks -alias "${HOSTNAME}" -certreq -file cert-file -storepass "${CREDS_VAL}"
#openssl x509 -req -CA ca-cert -CAkey ca-key -in cert-file -out cert-signed -days 3650 -CAcreateserial -subj '/C=HK/ST=HK/L=Hong\ Kong/O=CA\ Root\ 01/OU=CA_ROOT_01' -passin pass:abcd
openssl x509 -req -CA ca-cert -CAkey ca-key -in cert-file -out cert-signed -days "${DAYS}" -CAcreateserial -subj "${SUBJ_CERT}" -passin pass:"${CREDS_VAL}"
#keytool -keystore server.keystore.jks -alias CARoot -import -file ca-cert
keytool -keystore server.keystore.jks -alias CARoot -import -file ca-cert -storepass "${CREDS_VAL}" -noprompt
#keytool -keystore server.keystore.jks -alias localhost -import -file cert-signed
keytool -keystore server.keystore.jks -alias "${HOSTNAME}" -import -file cert-signed -storepass "${CREDS_VAL}" -noprompt

#Step4
echo "${CREDS_VAL}" >> "${CREDS_FILE}"



