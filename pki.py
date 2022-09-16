# http://pki-tutorial.readthedocs.org/en/latest/
# http://sheogora.blogspot.com/2012/03/m2crypto-for-python-x509-certificates.html

# get "M2Crypto" from: https://pypi.python.org/pypi/M2Crypto
# to use M2Crypto also need "setuptools" from : https://pypi.python.org/pypi/setuptools/3.6
# to use M2Crypto also need "swig": apt-get install swig

import time, base64, os
from M2Crypto import X509, EVP, RSA, ASN1

def issuer_name():
	"""
	CA issuer name (Distinguished Names).
	Parameters:
		none
	Return:
		X509 name of the issuer.
	"""
	issuer = X509.X509_Name()
	issuer.C = "US"				# country name
	issuer.CN = "ca_server"		# common name
	return issuer

def make_request(bits, cn):
	"""
	Create a X509 request.
	Parameters:
		bits = number of bits in RSA key
		cn = common name in request
	Return:
		X509 request and the private key (EVP).
	"""
	rsa = RSA.gen_key(bits, 65537, callback = lambda: None) # lambda to avoid user feedback
	pk = EVP.PKey()
	pk.assign_rsa(rsa)
	req = X509.Request()
	req.set_pubkey(pk)
	name = req.get_subject()
	name.C = "US"
	name.CN = cn
	req.sign(pk,'sha256')
	return req, pk

def make_certificate_valid(cert, days):
	"""
	Make a certificate valid for some days from now.
	Parameters:
		cert = certificate to make valid
		days = number of days cert is valid for from now
	Return:
		none
	"""
	t = long(time.time()) # get current time
	time_now = ASN1.ASN1_UTCTIME()
	time_now.set_time(t)
	time_exp = ASN1.ASN1_UTCTIME()
	time_exp.set_time(t + days * 24 * 60 * 60)
	cert.set_not_before(time_now)
	cert.set_not_after(time_exp)

def make_ca_certificate(bits):
	"""
	Make a CA certificate.
	Parameters:
		bits = number of bits in RSA key
	Return:
		CA certificate, CA private key (EVP) and CA public key (EVP).
	"""
	req, pk = make_request(bits, "localhost")
	puk = req.get_pubkey()
	cert = X509.X509()
	cert.set_serial_number(1) # self signed certificate is first
	cert.set_version(1)
	cert.set_issuer(issuer_name())
	cert.set_subject(issuer_name()) # same issuer and subject in self signed certificate
	cert.set_pubkey(puk)
	cert.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE')) # make it CA certificate
	make_certificate_valid(cert, 365) # certificate is valid for 1 year
	cert.sign(pk, 'sha256')
	return cert, pk, puk

def make_certificate(serial_number):
	"""
	Make a certificate.
	Parameters:
		serial_number = serial number of certificate
	Return:
		A new valid certificate to fill with data.
	"""
	cert = X509.X509()
	cert.set_serial_number(serial_number)
	cert.set_version(1)
	make_certificate_valid(cert, 365) # certificate is valid for 1 year
	return cert

# ==================================================

def pki_ca_init(ca_cert_loc, ca_pk_loc, ca_puk_loc):
	"""
	Create CA certificate, CA private key and CA public key. Save them as files.
	Parameters:
		ca_cert_loc = location of file to store CA certificate
		ca_pk_loc = location of file to store CA private key
		ca_puk_loc = location of file to store CA public key
	Return:
		none
	"""
	ca_cert, ca_pk, ca_puk = make_ca_certificate(1024)
	ca_cert.save_pem(ca_cert_loc)
	ca_pk.save_key(ca_pk_loc, cipher = None, callback = lambda: None)
	ca_puk.get_rsa().save_pub_key(ca_puk_loc)

def pki_ca_issue_certificate(cert_req_loc, ca_pk_loc, serial_number, cert_loc):
	"""
	Issue certificate based on the request and save it as a file.
	Serial number must not repeat in issued certificates.
	Parameters:
		cert_req_loc = location of file with certificate request
		ca_pk_loc = location of file with CA private key
		serial_number = serial number for the issued certificate
		cert_loc = location of file to store issued certificate
	Return:
		none
	"""
	ca_pk = EVP.load_key(ca_pk_loc)  # load EVP for signing certificates
	cert_req = X509.load_request(cert_req_loc)
	cert = make_certificate(serial_number)
	cert.set_subject(cert_req.get_subject())
	cert.set_pubkey(cert_req.get_pubkey())
	cert.sign(ca_pk, 'sha256')
	cert.save_pem(cert_loc)

def pki_request_certificate(id_name, cert_req_loc, pk_loc):
	"""
	Create a certificate request with public key and get a private key.
	Save certificate request and private key as files.
	Parameters:
		id_name = string to store as common name in certificate
		cert_req_loc = location of file to store certificate request
		pk_loc = location of file to store private key
	Return:
		none
	"""
	cert_req, pk = make_request(1024, cn = id_name)
	cert_req.save_pem(cert_req_loc)
	pk.save_key(pk_loc, cipher = None, callback = lambda: None)

def pki_verify_certificate(cert_loc, ca_cert_loc):
	"""
	Verifies a certificate by using CA certificate.
	Parameters:
		cert_loc = location of file with certificate to verify
		ca_cert_loc = location of file with CA certificate
	Return:
		1 if client certificate is valid, 0 otherwise.
	"""
	cert = X509.load_cert(cert_loc)
	ca_cert = X509.load_cert(ca_cert_loc)
	return cert.verify(ca_cert.get_pubkey())

def pki_encrypt_with_certificate(message, cert_loc):
	"""
	Encrypt a message by using a public key (certificate) so it can be decrypted only with the matching private key.
	Parameters:
		message = message to encrypt
		cert_loc = location of the file with certificate holding the public key
	Return:
		Encrypted message or string starting with "ERROR" in case of error.
	"""
	cert = X509.load_cert(cert_loc)
	puk = cert.get_pubkey().get_rsa() # get RSA for encryption
	message = base64.b64encode(message)
	try:
		encrypted = puk.public_encrypt(message, RSA.pkcs1_padding)
	except RSA.RSAError as e:
		return "ERROR encrypting " + e.message
	return encrypted

def pki_decrypt_with_private_key(message, pk_loc):
	"""
	Decrypt a message encrypted with a public key by using the matching private key.
	Parameters:
		message = message to decrypt
		pk_loc = location of the file with private key
	Return:
		Decrypted message or string starting with "ERROR" in case of error.
	"""
	pk = RSA.load_key(pk_loc) # load RSA for decryption
	try:
		decrypted = pk.private_decrypt(message, RSA.pkcs1_padding)
		decrypted = base64.b64decode(decrypted)
	except RSA.RSAError as e:
		return "ERROR decrypting " + e.message
	return decrypted

# ==================================================

# =====
# USAGE
# =====

# declare file locations

cert_dir = "certs"
if not os.path.exists(cert_dir):
	os.makedirs(cert_dir)

ca_cert = cert_dir + "/" + "ca_cert.pem"
ca_pk = cert_dir + "/" + "ca_pk.pem"
ca_puk = cert_dir + "/" + "ca_puk.pem"

cert1_req = cert_dir + "/" + "cert1_req.pem"
pk1 = cert_dir + "/" + "pk1.pem"
cert1 = cert_dir + "/" + "cert1.pem"

cert2_req = cert_dir + "/" + "cert2_req.pem"
pk2 = cert_dir + "/" + "pk2.pem"
cert2 = cert_dir + "/" + "cert2.pem"


# first initialize CA, creating CA certificate, CA public and CA private key
pki_ca_init(ca_cert, ca_pk, ca_puk)

# a client can request a certificate from CA, creating certificate request and client private key
pki_request_certificate("client1", cert1_req, pk1)
pki_request_certificate("client2", cert2_req, pk2)

# CA approves and issues the certificate for client
pki_ca_issue_certificate(cert1_req, ca_pk, 11, cert1)
pki_ca_issue_certificate(cert2_req, ca_pk, 12, cert2)

# a client can verify another client's certificate by using CA certificate
print "verify client1 certificate: %d" % pki_verify_certificate(cert1, ca_cert)
print "verify client2 certificate: %d" % pki_verify_certificate(cert2, ca_cert)
print ""

# test encryption and decryption
print "original message:"
message = "hello world"
print message + "\n"

# client can encrypt a message with other client's public key from certificate
print "message encrypted with client1 certificate:"
encrypted1 = pki_encrypt_with_certificate(message, cert1)
print encrypted1 + "\n"

# a message can be decrypted with client private key
print "message decrypted with client1 private key:"
decrypted1 = pki_decrypt_with_private_key(encrypted1, pk1)
print decrypted1 + "\n"

# decrypting with wrong private key should fail
print "message decrypted with client2 private key:"
decrypted2 = pki_decrypt_with_private_key(encrypted1, pk2)
print decrypted2 + "\n"