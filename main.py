#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import re
import binascii
import pefile
import struct

# http://msdl.microsoft.com/download/symbols/notepad.pdb/A976171302F1449EA6B676E127B7434D2/notepad.pdb

def to_pdb(filename):
	return re.sub(r'.exe$', '.pdb', os.path.basename(filename))

def build_url(filename):
	guid = ""
	pdb  = to_pdb(filename)
	pe   = pefile.PE("notepad.exe")

	for dbg in pe.DIRECTORY_ENTRY_DEBUG:
		# IMAGE_DEBUG_TYPE_CODEVIEW
		if dbg.struct.Type == 2:
			guid = '%s%s%s%s%s%s%s' % (
				binascii.hexlify(struct.pack('>I', dbg.entry.Signature_Data1)).upper(),
				binascii.hexlify(struct.pack('>H', dbg.entry.Signature_Data2)).upper(),
				binascii.hexlify(struct.pack('>H', dbg.entry.Signature_Data3)).upper(),
				binascii.hexlify(struct.pack('H', dbg.entry.Signature_Data4)).upper(),
				binascii.hexlify(struct.pack('H', dbg.entry.Signature_Data5)).upper(),
				binascii.hexlify(struct.pack('I', dbg.entry.Signature_Data6)).upper(),
				dbg.entry.Age)

			break

	# http://msdl.microsoft.com/download/symbols/notepad.pdb/A976171302F1449EA6B676E127B7434D2/notepad.pdb
	return 'http://msdl.microsoft.com/download/symbols/%s/%s/%s' % (pdb, guid, pdb)

def main():
	if len(sys.argv) < 2:
		print "Usage: %s /tmp/notepad.exe /tmp/kernel32.dll" % (sys.argv[0])
		return

	for filename in sys.argv[1:]:
		downurl  = build_url(filename)
		destfile = os.path.dirname(os.path.abspath(filename)) + "/" + to_pdb(filename)

		print "Saving %s to %s" % (downurl, destfile)
		os.system ("curl -L %s -o %s" % (downurl, destfile))

if __name__ == '__main__':
	main()
