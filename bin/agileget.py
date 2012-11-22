#!/usr/bin/env python

import urllib2
import os, random, struct
from AgileCLU import AgileCLU
from Crypto.Cipher import AES
from optparse import OptionParser, OptionGroup


def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)

def main(*arg):
	parser = OptionParser( usage= "usage: %prog [options] object path", version="%prog (AgileCLU "+AgileCLU.__version__+")")
	parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="be verbose", default=False)
	parser.add_option("-l", "--login", dest="username", help="use alternate profile")
	(options, args) = parser.parse_args()

	if len(args) != 2: parser.error("Wrong number of arguments. Exiting.")
        object = args[0]
        path = args[1]

	if options.username: agile = AgileCLU( options.username )
	else: agile = AgileCLU()

	egress=agile.mapperurl
	lfilename = os.path.split(object)[1]
	u = urllib2.urlopen(egress + object )
	dfile = os.path.join(path, lfilename)
	f = open(dfile, 'wb')
	f.write(u.read())
	f.close()
	filename, fileext = os.path.splitext(dfile)
	if(fileext == '.enc'):
		decrypt_file(agile.encryptionpassword, dfile)

if __name__ == '__main__':
    main()
