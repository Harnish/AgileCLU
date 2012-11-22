#!/usr/bin/env python

from AgileCLU import AgileCLU
from optparse import OptionParser, OptionGroup
import sys, os.path, urllib, subprocess, time, gzip, random, struct, io, json
from Crypto.Cipher import AES

from poster.encode import multipart_encode, get_body_size
from poster.streaminghttp import register_openers
from urllib2 import Request, urlopen, URLError, HTTPError

def main(*arg):

	global fname
	# parse command line and associated helper

	parser = OptionParser( usage= "usage: %prog [options] object path", version="%prog (AgileCLU "+AgileCLU.__version__+")")
	parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="be verbose", default=False)
        parser.add_option("-l", "--login", dest="username", help="use alternate profile")

	group = OptionGroup(parser, "Handling Options")
	group.add_option("-r", "--rename", dest="filename", help="rename destination file")
	group.add_option("-c", "--mimetype", dest="mimetype", help="set MIME content-type")
	group.add_option("-t", "--time", dest="mtime", help="set optional mtime")
	group.add_option("-e", "--egress", dest="egress", help="set egress policy (PARTIAL, COMPLETE or POLICY)", default="COMPLETE")
	group.add_option("-m", "--mkdir", action="store_true", help="create destination path, if it does not exist")
	group.add_option("-p", "--progress", action="store_true", help="show transfer progress bar")
	group.add_option("-z", "--zip", action="store_true", help="compress file before uploading. Including encrypted")
	group.add_option("-s", "--encrypt", action="store_true", help="Encrypt file before sending it up")
	parser.add_option_group(group)
	
	config = OptionGroup(parser, "Configuration Option")
	config.add_option("--username", dest="username", help="Agile username")
	config.add_option("--password", dest="password", help="Agile password")
	config.add_option("--mapperurl", dest="mapperurl", help="Agile MT URL base")
	config.add_option("--apiurl", dest="apiurl", help="Agile API URL")
	config.add_option("--posturl", dest="posturl", help="Agile POST URL")
	parser.add_option_group(config)

	(options, args) = parser.parse_args()
	if len(args) != 2: parser.error("Wrong number of arguments. Exiting.")
	object = args[0]
	path = args[1]
	
	if (not os.path.isfile(object)):
		print "Local file object (%s) does not exist. Exiting." % object
		sys.exit(1)

	if options.username: agile = AgileCLU( options.username )
	else: agile = AgileCLU()

	localpath = os.path.dirname(object)
	localfile = os.path.basename(object)

	if( options.encrypt ):
		encrypt_file(agile.encryptionpassword, os.path.join(localpath,localfile))
		localfile += ".enc"

	if( options.zip ):
		if options.verbose: print "Compressing %s" % (localfile)
		f_in = open(os.path.join(localpath,localfile), 'rb')
		localfile += ".gz"
		f_out = gzip.open(os.path.join(localpath,localfile), 'wb')
		f_out.writelines(f_in)
		f_out.close()
		f_in.close()

	# check that destination path exists
	if (not agile.exists(path)):
		if options.mkdir: 
			r = agile.mkdir( path, 1 )
			if (r):
				if options.verbose: print "Destination path (%s) has been created. Continuing..." % path
			else:
				if options.verbose: print "Destination path (%s) failed to be created. Suggest trying --mkdir option. Exiting." % path
				agile.logout()
				sys.exit(2)
		else:
			if options.verbose: print "Destination path (%s) does not exist. Suggest --mkdir option. Exiting." % path
			agile.logout()
			sys.exit(1)
	
	if options.filename: fname = options.filename
	else: fname = localfile

	if options.mimetype: mimetype = options.mimetype
	else: mimetype = 'auto'

	if options.progress: callback = agile.pbar_callback
	else: callback = None

	try:
		result = agile.post( os.path.join(localpath,localfile), path, fname, mimetype, None, options.egress, False, callback )
	except (KeyboardInterrupt, SystemExit):
		print "\nInterupted..."
		sys.exit(1)

	if options.verbose: print "%s%s" % (agile.mapperurlstr(),urllib.quote(os.path.join(path,fname)))

	agile.logout()
	if( options.zip ):
		if options.verbose: print "Clearing cached zip file"
		os.remove(os.path.join(localpath,localfile))


def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))



if __name__ == '__main__':
    main()


