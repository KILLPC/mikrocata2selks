# 1. Generate the ECDSA P-256 (prime256v1) private key
openssl ecparam -name prime256v1 -genkey -out utmca.key

# 2. Generate the self-signed CA certificate
openssl req -new -x509 -days 3650 -config ca.cnf -key utmca.key -out utmca.crt


#Create leaf key
openssl ecparam -name prime256v1 -genkey -out leaf.key
