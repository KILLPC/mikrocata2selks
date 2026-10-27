# 1. Generate the ECDSA P-256 (prime256v1) private key
#EC keys. Note that some browser will use EKU flags and may not work. Uncomment if you still want to use it.
#openssl ecparam -name prime256v1 -genkey -out utmca.key

openssl genrsa -out utmca.key 2048

# 2. Generate the self-signed CA certificate
openssl req -new -x509 -days 3650 -config ca.cnf -key utmca.key -out utmca.crt



#Create leaf key
#EC leaf.
#openssl ecparam -name prime256v1 -genkey -out leaf.key

openssl genrsa -out leaf.key 2048
