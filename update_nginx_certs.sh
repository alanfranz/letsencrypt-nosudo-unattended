#!/bin/bash

#configuration
NGINX_CONFDIR=/etc/nginx/sites-enabled
NGINX_CERTDIR=/etc/nginx/ssl
LETSENCRYPT_CERTDIR=/opt/letsencrypt-nosudo/certs
LETSENCRYPT_INTERMEDIATE_DIR=/opt/letsencrypt-nosudo/intermediates

#get a list of configured ssl vhosts
sslcerts=$(grep "ssl_certificate " $NGINX_CONFDIR/* | awk '{print $3}' | sed 's/;$//' | sort | uniq)

#track if we have to restart apache
anything_changed=0

#loop through all certs
for sslcert in $sslcerts; do
  #get domain name
  domain=$(basename $sslcert .pem)
  
  #ignore cert if not controlled by letsencrypt
  [ -e $LETSENCRYPT_CERTDIR/$domain.crt ] || continue

  #get issuer of new certificate
  issuer=$(openssl x509 -in $LETSENCRYPT_CERTDIR/$domain.crt -noout -issuer | cut -d= -f2-)
  [ $? -eq 0 ] || { echo "Unable to get issuer of $LETSENCRYPT_CERTDIR/$domain.crt"; continue; }

  #find right intermediate certificate
  intermediate_cert=""
  for intermediate in $LETSENCRYPT_INTERMEDIATE_DIR/*; do
    openssl x509 -subject -noout -in $intermediate | grep -q "$issuer"
    if [ $? -eq 0 ]; then
      intermediate_cert=$intermediate
      break
    fi
  done
  [ "$intermediate_cert" = "" ] && { echo "Unable to find intermediate certificate $issuer for $LETSENCRYPT_CERTDIR/$domain.crt"; continue; }

  #if cert already exists do some checks
  if [ -e $sslcert ]; then
    #ignore cert if md5 sums match or are empty
     oldcert_md5sum=$(md5sum $sslcert | cut -d" " -f1)
     newcert_md5sum=$(cat $LETSENCRYPT_CERTDIR/$domain.crt $intermediate_cert | md5sum | cut -d" " -f1)
     if [ -z $oldcert_md5sum ] || [ -z $newcert_md5sum ] || [ "$oldcert_md5sum" == "$newcert_md5sum" ]; then
       continue
     fi

     #get common names of old and new certificates
     oldcert_cn=$(openssl x509 -noout -subject -in $sslcert | cut -d= -f3)
     [ $? -eq 0 ] || { >&2 echo "Error while getting common name of $sslcert"; continue; }
     newcert_cn=$(openssl x509 -noout -subject -in $LETSENCRYPT_CERTDIR/$domain.crt | cut -d= -f3)
     [ $? -eq 0 ] || { >&2 echo "Error while getting common name of $LETSENCRYPT_CERTDIR/$domain.crt"; continue; }

     #check if common names match domain name
     [ "$oldcert_cn" = "$domain" ] || { >&2 echo "CN of old certificate $oldcert_cn does not match domain name $domain"; continue; }
     [ "$newcert_cn" = "$domain" ] || { >&2 echo "CN of new certificate $newcert_cn does not match domain name $domain"; continue; }

     #get expiration dates of old and new certificates
     oldcert_enddate_string=$(openssl x509 -noout -enddate -in $sslcert | cut -d= -f2; exit ${PIPESTATUS[0]})
     [ $? -eq 0 ] || { >&2 echo "Error while getting enddate of $sslcert"; continue; }
     newcert_enddate_string=$(openssl x509 -noout -enddate -in $LETSENCRYPT_CERTDIR/$domain.crt | cut -d= -f2; exit ${PIPESTATUS[0]})
     [ $? -eq 0 ] || { >&2 echo "Error while getting enddate of $LETSENCRYPT_CERTDIR/$domain.crt"; continue; }

     #convert expiration dates to timestamp
     oldcert_enddate=$(date --date="$oldcert_enddate_string" "+%s")
     [ $? -eq 0 ] || { >&2 echo "Error getting timestamp of $oldcert_enddate_string"; continue; }
     newcert_enddate=$(date --date="$newcert_enddate_string" "+%s")
     [ $? -eq 0 ] || { >&2 echo "Error getting timestamp of $newcert_enddate_string"; continue; }

     #compare expiration dates
     [ $oldcert_enddate -gt $newcert_enddate ] && { >&2 echo "Old certificate $sslcert expires after new certificate $LETSENCRYPT_CERTDIR/$domain.crt"; continue; }

  fi

  #check if new key belongs to new certificate by comparing their md5 hashes
  newcert_md5hash=$(openssl x509 -in $LETSENCRYPT_CERTDIR/$domain.crt -noout -modulus | openssl md5)
  newkey_md5hash=$(openssl rsa -in $LETSENCRYPT_CERTDIR/$domain.key -noout -modulus 2>/dev/null | openssl md5)
  [ "$newcert_md5hash" = "$newkey_md5hash" ] || { >&2 echo "Key $LETSENCRYPT_CERTDIR/$domain.key does not belong to certificate $LETSENCRYPT_CERTDIR/$domain.crt"; continue; }

  #copy certificates to nginx ssl config dir
  cp -a $LETSENCRYPT_CERTDIR/$domain.key $NGINX_CERTDIR/
  [ $? -eq 0 ] || { echo "CRITICAL - Error while copying $LETSENCRYPT_CERTDIR/$domain.key to $NGINX_CERTDIR - investigate manually"; exit 2; }
  cat $LETSENCRYPT_CERTDIR/$domain.crt $intermediate_cert > $NGINX_CERTDIR/$domain.pem
  [ $? -eq 0 ] || { echo "CRITICAL - Error while merging $LETSENCRYPT_CERTDIR/$domain.crt $LETSENCRYPT_X1_INTERMEDIATE into $NGINX_CERTDIR/$domain.pem - investigate manually"; exit 2; }

  echo "Certificate for $domain updated"
  anything_changed=1
done

#restart apache if anything had been changed
if [ $anything_changed -eq 1 ]; then
  #check if we are on systemd enabled host
  systemctl=$(which systemctl)
  if [ $? -eq 0 ]; then
    systemctl restart nginx
  else
    /etc/init.d/nginx restart
  fi

  #check if restart succeeded
  [ $? -eq 0 ] || { echo "CRITICAL - Error while restarting Apache"; exit 2; }
fi
