# RSA CONVERTER

Python script that converts RSA PEM key (PKCS#1) to XML and Vice Versa

## Requirements:
2. pycrypto


"""
Need pycrypto installed | - pip install pycrypto



EXAMPLES

- Convert a public key from XML to PEM: python3 rsa_converter.py -xtop -pub "path/to/public.xml"
- Convert a private key from XML to PEM: python3 rsa_converter.py -xtop -priv "path/to/private.xml"

- Convert a public key from PEM to XML: python3 rsa_converter.py -ptox -pub "path/to/public.pem"
- Convert a private key from PEM to XML: python3 rsa_converter.py -ptox -priv "path/to/private.pem"

"""
