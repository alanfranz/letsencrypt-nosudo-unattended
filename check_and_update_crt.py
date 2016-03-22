#!/usr/bin/env python
import argparse, subprocess, json, os, urllib2, sys, base64, binascii, time, \
    hashlib, tempfile, re, copy, textwrap, ConfigParser, re, stat


def check_and_update_crt(config):

    """Checks if Letsencrypt certificates have to be updated

    :param list config: configuration data

    """

    certDir = config['certDir']
    domains = config['domains'].split("\n")
    renewBefore = config['renewBeforeDaysLeft']
    
    scriptPath = os.path.dirname(os.path.realpath(sys.argv[0]))
        
    for domain in domains:
        certFile = certDir + "/" + domain + ".crt"

	if os.path.isfile(certFile):
	    proc = subprocess.Popen(["openssl", "x509", "-noout", "-dates", "-in", certFile ],
    	    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	    out, err = proc.communicate()
    	    if proc.returncode != 0:
    		raise IOError("Error checking certificate {0}".format(certFile))
    		
    	    p = re.compile(r"^notAfter=(.+)$", re.MULTILINE)
    	    m = p.search(out)
    	    if m:
    		expirationDateReadable = m.group(1)
    		
    		now = time.time()
    		expirationDate = time.strptime(expirationDateReadable, "%b %d %H:%M:%S %Y %Z")
    		expirationDate = time.mktime(expirationDate)
    		
    		diff = expirationDate - now
    		
    		daysLeft = int(diff/3600/24)
    		
	        sys.stdout.write("Certificate for " + domain + " expires in " + str(daysLeft) + " day(s) [" + expirationDateReadable  + "]\n")
	        
    		if daysLeft > renewBefore:
    		    continue

        sys.stdout.write("Renewing certificate for " + domain + "...\n")

        sys.stdout.write("Generating new key...\n")
        keyFileName = certDir + "/" + domain + ".key"
        proc = subprocess.Popen(["openssl", "genrsa", "-out", keyFileName, "4096" ],
	stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = proc.communicate()
    	if proc.returncode != 0:
    	    raise IOError("Error creating key at {0}".format(keyFileName))
	os.chmod(keyFileName, stat.S_IREAD | stat.S_IWRITE);

        sys.stdout.write("Creating certificate request...\n")
        csrFileName = certDir + "/" + domain + ".csr"   
        proc = subprocess.Popen(["openssl", "req", "-new", "-sha256", "-key", keyFileName, "-subj", "/CN=" + domain, "-out", csrFileName ],
	stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = proc.communicate()
    	if proc.returncode != 0:
    	    raise IOError("Error creating CSR at {0}".format(csrFileName))
	os.chmod(csrFileName, stat.S_IREAD | stat.S_IWRITE);

        sys.stdout.write("Running sign_csr.py...\n")
	proc = subprocess.Popen(["python", scriptPath + "/sign_csr.py", csrFileName ],
	stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = proc.communicate()
    	if proc.returncode != 0:
	    raise IOError("Error running {0}/sign_csr.py when requesting certificate for {1}\nstdout: {2}\n stderr: {3}\n".format(scriptPath, domain, out, err))
	if os.path.isfile(certFile):
    	    sys.stdout.write("New certificate stored at " + certFile + "\n")
    	else:
    	    sys.stderr.write("Something strange happened - sign_csr.py returned no error but " + certFile + " does not exist.\n")

	os.chmod(certFile, stat.S_IREAD | stat.S_IWRITE);

    return

if __name__ == "__main__":

    Config = ConfigParser.ConfigParser()
    Config.read(os.path.dirname(os.path.realpath(sys.argv[0])) + '/letsencrypt-nosudo.conf')
    
    config = {}
    config['certDir'] = Config.get('directories', 'certDir')
    config['domains'] = Config.get('main', 'domains')
    config['renewBeforeDaysLeft'] = int(Config.get('renew', 'renewBeforeDaysLeft'))
    
    check_and_update_crt(config)
