#!/bin/bash

#configuration
APACHE_CONFDIR=/etc/apache2/sites-enabled
APACHE_CERTDIR=/etc/apache2/ssl
LETSENCRYPT_CERTDIR=/opt/letsencrypt-nosudo/certs

#get a list of configured ssl vhosts
sslcerts=$(grep SSLCertificateFile $APACHE_CONFDIR/*.conf | awk '{print $3}' | sort | uniq)

#track if we have to restart apache
anything_changed=0

#loop through all certs
for sslcert in $sslcerts; do
  #get domain name
  domain=$(basename $sslcert .crt)
  
  #ignore cert if not controlled by letsencrypt
  [ -e $LETSENCRYPT_CERTDIR/$domain.crt ] || continue

  #if cert already exists do some checks
  if [ -e $sslcert ]; then
    #ignore cert if md5 sums match or are empty
    oldcert_md5sum=$(md5sum $sslcert | cut -d" " -f1)
    newcert_md5sum=$(md5sum $LETSENCRYPT_CERTDIR/$domain.crt | cut -d" " -f1)
    if [ -z $oldcert_md5sum ] || [ -z $newcert_md5sum ] || [ "$oldcert_md5sum" == "$newcert_md5sum" ]; then
      continue
    fi
  
    #get common names of old and new certificates
    oldcert_cn=$(openssl x509 -noout -subject -in $sslcert | cut -d= -f3)
    [ $? -eq 0 ] || { >&2 echo "Error while getting common name of $sslcert"; continue; }
    newcert_cn=$(openssl x509 -noout -subject -in $LETSENCRYPT_CERTDIR/$domain.crt | cut -d= -f3)
    [ $? -eq 0 ] || { >&2 echo "Error while getting common name of $LETSENCRYPT_CERTDIR/$domain.crt"; continue; }
  
    #check if common names match domain name
    [ "$oldcert_cn" == "$domain" ] || { >&2 echo "CN of old certificate $oldcert_cn does not match domain name $domain"; continue; }
    [ "$newcert_cn" == "$domain" ] || { >&2 echo "CN of new certificate $newcert_cn does not match domain name $domain"; continue; }
  
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
  [ "$newcert_md5hash" == "$newkey_md5hash" ] || { >&2 echo "Key $LETSENCRYPT_CERTDIR/$domain.key does not belong to certificate $LETSENCRYPT_CERTDIR/$domain.crt"; continue; }

  #copy certificates to apache ssl config dir
  cp -a $LETSENCRYPT_CERTDIR/$domain.{crt,key} $APACHE_CERTDIR/
  [ $? -eq 0 ] || { echo "CRITICAL - Error while copying $LETSENCRYPT_CERTDIR/$domain.{crt,key} to $APACHE_CERTDIR - investigate manually"; exit 2; }

  echo "Certificate for $domain updated"
  anything_changed=1
done

#restart apache if anything had been changed
if [ $anything_changed -eq 1 ]; then
  #check if we are on systemd enabled host
  systemctl=$(which systemctl)
  if [ $? -eq 0 ]; then
    systemctl restart apache2
  else
    /etc/init.d/apache2 restart
  fi

  #check if restart succeeded
  [ $? -eq 0 ] || { echo "CRITICAL - Error while restarting Apache"; exit 2; }
fi
