#!/usr/bin/perl
# exec_elf64.pl
# written by isra - isra _replace_by_@_ fastmail.net - https://hckng.org
#
# https://git.sr.ht/~hckng/elf/tree/master/item/exec_elf64.pl
# https://github.com/ilv/elf/blob/main/exec_elf64.pl
# 
# version 0.1 - 2023
#
# in-memory-only fd-less ELF execution:
#
#  - read, parse, map, and execute a hardcoded ELF x64 object
#  - supports relocation and external symbols (from glibc)
#  - uses Perl v5.008001 or higher
#  - only standard modules are used
#
# to run:
#     $ perl exec_elf64.pl
#
# or (full fd-less):
#     $ echo BASE64_ENCODED_CONTENT | base64 -d | perl
#
# thanks to tmp0ut and vxug for all the resources
#


use DynaLoader;
#use Devel::Peek;
use 5.008001; # because 5.6 doesn't have B::PV::object_2svref
use Config;
use B (); # for B::PV
use strict;


###############################################################################
# read elf
###############################################################################

sub read_elf {
    # uncomment below to open ELF as a regular file
    #my $in = pop (@ARGV);
    #my $code = "";

    #open my $fh, '<:raw', $in;
    #$code .= $_ while(<$fh>);
    #close $fh;

    #open my $fh, '<:raw', $in;

    my $code = get_code();
    open my $fh, '<:raw', \$code;

    return ($code, $fh);
}


###############################################################################
# parse elf x64
# reference: https://github.com/lampmanyao/readelf/blob/master/readelf.pl
###############################################################################

####### global variables #######

# arrays for section header table, symbol header table, relocations
my (@shtab, @symtab, @relocs);
# hashes for elf header, string table, external symbols, functions
my (%ehdr, %strtab, %extsym, %funcs);

# indexes for relevant segments on the section header table
my ($text_ndx, $data_ndx, $rodata_ndx, $symtab_ndx, $relatext_ndx);

# number of external symbols
my $num_extsym = 0;

# shared library to lookup external symbols
# only glibc for now
my $libc_path = "/usr/lib/x86_64-linux-gnu/libc.so.6";
my $libref = DynaLoader::dl_load_file($libc_path, 0x01);

# elf file handler
my $efh;

####### keys for relevant hashes #######

# elf header keys
my @e_keys = (
    'ei_mag0', 'ei_mag1', 'ei_mag2', 'ei_mag3', 'ei_class', 'ei_data', 
    'ei_version', 'ei_osabi', 'ei_abiversion', #ei_pad ignored
    'e_type', 'e_machine', 'e_version', 'e_entry', 'e_phoff', 'e_shoff',
    'e_flags', 'e_ehsize', 'e_phentsize', 'e_phnum', 'e_shentsize', 'e_shnum',
    'e_shstrndx'
);

# section header keys
my @sh_keys = (
    'sh_name', 'sh_type', 'sh_flags', 'sh_addr', 'sh_offset', 'sh_size',
    'sh_link', 'sh_info', 'sh_addralign', 'sh_entsize'
);

# symbol table keys
my @st_keys = (
    'st_name', 'st_info', 'st_other', 'st_shndx', 'st_value', 'st_size'
);

# relocations keys
my @r_keys = ('r_offset', 'r_info', 'r_addend');


####### auxiliary subroutines #######

# read & unpack binary content
sub ru {
    my $fh  = shift;
    my $tpl = shift;
    my $sz  = shift;

    read $fh, my $buff, $sz;
    return unpack($tpl, $buff);
}

# make hash to easily handle various headers 
sub mk_hash {
    my $hashref = shift;
    my $keysref = shift;
    my $valsref = shift;

    for(my $i = 0; $i < @{$keysref}; $i++) {
        $hashref->{$keysref->[$i]} = $valsref->[$i];
    }
}

# parse elf header
# see https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
sub parse_ehdr {
    my @hdr = ru($efh, "C a a a C C C C C x7 S S I q q q I S S S S S S", 0x40);
    mk_hash(\%ehdr, \@e_keys, \@hdr);
}

# parse section header table
# see https://refspecs.linuxbase.org/elf/gabi4+/ch4.sheader.html
sub parse_shtab {
    seek $efh, $ehdr{'e_shoff'}, "SEEK_SET"; 
    for (my $i = 0; $i < $ehdr{'e_shnum'}; $i++) {
        my %sh;
        my @hdr = ru($efh, "I I q q q q I I q q", $ehdr{'e_shentsize'});
        mk_hash(\%sh, \@sh_keys, \@hdr);
        push @shtab, \%sh;

        # read content of section header entry of type 'STRTAB'
        if($sh{'sh_type'} == 3) {
            my $tmpstr;
            my $curr_offset = tell $efh;
            seek $efh, $sh{'sh_offset'}, "SEEK_SET";
            read $efh, $tmpstr, $sh{'sh_size'};
            seek $efh, $curr_offset, "SEEK_SET";
            $strtab{$sh{'sh_offset'}} = $tmpstr;
        }
    }
}

# get section name
sub secname {
    my $ndx = shift;
    my $str = shift;

    my $s = substr($str, $ndx);
    my $r = substr($s, 0, index($s, "\0"));
}

# parse section names from string table
sub parse_secnames {
    my $shstrtab = $shtab[$ehdr{'e_shstrndx'}];
    for(my $i = 0; $i < $ehdr{'e_shnum'}; $i++) {
        my $name = secname(
            $shtab[$i]{'sh_name'}, 
            $strtab{$shstrtab->{'sh_offset'}}
        );
        # add 'name' to each section header entry
        $shtab[$i]{'name'} = $name;

        # save indexes for easier access to relevant segments
        $text_ndx       = $i if($name eq '.text');
        $data_ndx       = $i if($name eq '.data');
        $symtab_ndx     = $i if($name eq '.symtab');
        $rodata_ndx     = $i if($name eq '.rodata');
        $relatext_ndx   = $i if($name eq '.rela.text');
    }
}

# parse symbol table
# see https://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html
sub parse_symtab {
    my $symtab      = $shtab[$symtab_ndx];
    my $sh_link     = $shtab[$symtab->{'sh_link'}];
    my $num_entry   = $symtab->{'sh_size'}/$symtab->{'sh_entsize'};

    my $curr_file_offset = tell $efh;
    seek $efh, $symtab->{'sh_offset'}, "SEEK_SET";
    for (my $i = 0; $i < $num_entry; $i++) {
        my %sym;
        my @hdr = ru($efh, "I C C S q q", $symtab->{'sh_entsize'});
        mk_hash(\%sym, \@st_keys, \@hdr);

        my $type = $sym{'st_info'} & 0x0f;
        my $name = secname(
            $sym{'st_name'}, 
            $strtab{$sh_link->{'sh_offset'}}
        );
        # add 'name' to each symbol 
        $sym{'name'} = $name;
        push @symtab, \%sym;

        # save st_value of symbols of type 'FUNC'
        $funcs{$name} = $sym{'st_value'} if($type == 2);
    }
    seek $efh, $curr_file_offset, "SEEK_SET";
}

# parse relocations
# see https://refspecs.linuxbase.org/elf/gabi4+/ch4.reloc.html
sub parse_relocs {
    my $rt = $shtab[$relatext_ndx];
    my $entry_num = $rt->{'sh_size'}/$rt->{'sh_entsize'};

    my $curr_file_offset = tell $efh;
    seek $efh, $rt->{'sh_offset'}, "SEEK_SET";
    for (my $i = 0; $i < $entry_num; $i++) {
        my %r;
        my @hdr = ru($efh, "q Q i", $rt->{'sh_entsize'});
        mk_hash(\%r, \@r_keys, \@hdr);

        # 4 bytes on little endian order 
        my $sym_ndx = unpack("V", pack("N", $r{'r_info'} >> 8));
        # low-order bits only
        my $type = $r{'r_info'} & 0x0f; 
        my $sym_name = $symtab[$sym_ndx]{'name'};
        my $sym_shndx = $symtab[$sym_ndx]{'st_shndx'};

        $r{'type'} = $type;
        $r{'symndx'} = $sym_ndx;
        push @relocs, \%r;

        # save external symbols (st_shndx of type 'UND')
        # the num_extsym counter is used later for lookup in a 'jump table'
        $extsym{$sym_name} = $num_extsym++ if($sym_shndx == 0);
    }
    seek $efh, $curr_file_offset, "SEEK_SET";
}

# glue it all together
sub parse_elf {
    my $fh = shift;
    $efh = $fh;
    
    parse_ehdr();
    parse_shtab();
    parse_secnames();
    parse_symtab();
    parse_relocs();
}


###############################################################################
# peek & poke 
#
# original code by Nick Landers
# https://gist.github.com/monoxgas/c0b0f086fc7aa057a8256b42c66761c8
#
# adapted for Linux x64 by isra
# most of the comments are from the original author
###############################################################################

# pack value into an unsigned qual value (for memory addresses)
sub _pack_address {
    my $p = pack("Q", $_[0]);
    return $p;
}

# convert value into a SvPV
sub peek {
    unpack "P$_[1]", _pack_address($_[0]);
}

# copy $bytes of length $len into address $location
sub poke {
    my($location, $bytes, $len) = @_;
    my $addr = _pack_address($location);
    # construct a B::PV object, backed by a SV/SvPV to a dummy string 
    # length($bytes) long, and substitute $location as the actual string
    # storage we specifically use the same length so we do not have to
    # deal with resizing
    my $dummy = 'X' x $len;
    my $dummy_addr = \$dummy + 0;
    my $ghost_sv_contents = peek($dummy_addr, 8 + 4 + 4 + $Config{ivsize});


    substr( $ghost_sv_contents, 8 + 4 + 4, 8 ) = $addr;    

    my $ghost_string_ref = bless( \ unpack(
        "Q",
        # it's crucial to create a copy of $sv_contents, and work with a
        # temporary memory location. Otherwise perl memory allocation will
        # kick in and wreak considerable havoc culminating with an inevitable
        # segfault
        do { no warnings 'pack'; pack( 'P', $ghost_sv_contents.'' ) },
    ), 'B::PV' )->object_2svref;
    # now when we write to the newly created "string" we are actually writing
    # to $location. note we HAVE to use lvalue substr - a plain assignment will
    # add a \0
    #
    # Also in order to keep threading on perl 5.8.x happy we *have* to perform
    # this in a string eval. I don't have the slightest idea why :)    
    eval 'substr($$ghost_string_ref, 0, $len) = $bytes';
    return $len;
}


###############################################################################
# map elf x64
#
# references:
#  - https://blog.cloudflare.com/how-to-execute-an-object-file-part-1/
#  - https://blog.cloudflare.com/how-to-execute-an-object-file-part-2/
#  - https://blog.cloudflare.com/how-to-execute-an-object-file-part-3/ 
###############################################################################

# 4K pages 
sub page_align {
    my $n = shift;
    return ($n + (4096 - 1)) & ~(4096 - 1);
}

# memory map
sub mmap {
    # syscall number for mmap is 9 on Linux x86_64
    # $addr can be a fixed value, or 0 to let mmap choose one
    # it returns a pointer to the mapped area on success, -1 on failure
    my ($addr, $size, $protect, $flags) = @_;
    my $ret = syscall(9, $addr, $size, $protect, $flags, -1, 0);
    return $ret;
}

# memory protect
sub mprotect {
    # it returns 0 on success, -1 on failure
    my ($addr, $size, $protect) = @_;
    my $ret = syscall(10, $addr, $size, $protect);
    return $ret;
}

# calculate and apply relocations
sub do_relocs {
    # pointers to mapped segments and 'jump table'
    my $text_ptr    = shift;
    my $data_ptr    = shift;
    my $rodata_ptr  = shift;
    my $jmptab_ptr  = shift;
    my $rt          = $shtab[$relatext_ndx];
    my $num_relocs  = $rt->{'sh_size'}/$rt->{'sh_entsize'};
 
    for (my $i = 0; $i < $num_relocs; $i++) {
        # where to patch .text 
        my $sym_ndx = $relocs[$i]{'symndx'};
    
        # symbol and section with respect to which the relocation is performed
        # external symbols are identified by st_shndx == 0 (type UND)
        my $sym_name = $symtab[$sym_ndx]{'name'};
        my $sym_shndx = $symtab[$sym_ndx]{'st_shndx'};
        my $sec_name = $shtab[$sym_shndx]{'name'};

        if($sec_name eq '.text' || $sec_name eq '.data' 
            || $sec_name eq '.rodata' || $sym_shndx == 0) {
            my $base_ptr;
            my $patch_offset = $text_ptr + $relocs[$i]{'r_offset'};

            $base_ptr = $text_ptr if($sec_name eq '.text');
            $base_ptr = $data_ptr if($sec_name eq '.data');
            $base_ptr = $rodata_ptr if($sec_name eq '.rodata');

            my $sym_addr;
            if($sym_shndx != 0) {
                $sym_addr = $base_ptr + $symtab[$sym_ndx]{'st_value'};
            } else {
                # external symbols

                # a 'jump table' is used for jumping to external addresses
                # each entry on the 'jump table' uses 14 bytes: 8 bytes for
                # the external address where to jump + 6 bytes for the jump
                # instruction

                # offset on the 'jump table' is calculated based on the number
                # of external symbols; first entry starts at offset 0, second
                # at offset 14, third at offset 28, and so on and so forth
                my $jmptab_ndx = $jmptab_ptr + ($extsym{$sym_name}*14);

                # the symbol address used for the relocation formula should
                # point to the jump instruction in the 'jump table' entry, thus
                # the first 8 bytes are skipped
                $sym_addr = $jmptab_ndx + 8;

                # the actual external symbol address 
                my $ext_addr = DynaLoader::dl_find_symbol($libref, $sym_name);

                # pack address in little endian order and then append the jump:
                # 0xff 0x25 for the instruction itself and 0xfffffff2 = -14 for
                # the offset (jump 14 bytes backwards to the external address)

                # "V" format is 4 bytes; external address is 8 bytes
                my ($p1, $p2) = unpack("V2", pack("Q", $ext_addr));
                my $jmptab_entry = pack("V", $p1);
                $jmptab_entry .= pack("V", $p2);
                $jmptab_entry .= "\xff\x25\xf2\xff\xff\xff";

                # update 'jump table' in memory
                poke($jmptab_ndx, $jmptab_entry, length($jmptab_entry));
            }
     
            # R_X86_64_PLT32 (4) and R_X86_64_PC32 (2) relocations
            # it uses the formulae L + A - P and S + A - P, assuming L = S
            if($relocs[$i]{'type'} == 4 or $relocs[$i]{'type'} == 2) {
                my $relo = $sym_addr + $relocs[$i]{'r_addend'} - $patch_offset;
                # pack in little endian order (4 bytes)
                $relo = pack("V", $relo);
                # apply relocation by simply copying the calculated address
                # into the patch offset address
                poke($patch_offset, $relo, length($relo));
            }
        } 
    }
}

# map code (memory map, poke code, relocate, memory protect)
sub map_elf {
    my $code = shift;

    my $base_ptr = mmap(0, length($code), 3, 33);
    if($base_ptr == -1) {
        print "Failed to allocate memory for ELF\n";
        exit;
    }

    poke($base_ptr, $code, length($code));

    my $text    = $shtab[$text_ndx];
    my $data    = $shtab[$data_ndx];
    my $rodata  = $shtab[$rodata_ndx];

    # size of 'jump table' is number of external symbols * 14 bytes
    my $jmptab_size = $num_extsym*14;

    # map segments and 'jump table' next to each other
    my $text_ptr = mmap(
        0, 
        page_align($text->{'sh_size'}) + 
        page_align($data->{'sh_size'}) + 
        page_align($rodata->{'sh_size'}) +
        page_align($jmptab_size), 
        3, 
        33
    );
    if ($text_ptr == -1) {
        print "Failed to allocate memory for .text\n";
        exit;
    }
    
    my $data_ptr   = $text_ptr + page_align($text->{'sh_size'});
    my $rodata_ptr = $data_ptr + page_align($data->{'sh_size'});
    my $jmptab_ptr = $rodata_ptr + page_align($rodata->{'sh_size'});

    # copy segments into memory
    poke(
        $text_ptr, 
        substr($code, $text->{'sh_offset'}, $text->{'sh_size'})
    );

    poke(
        $data_ptr, 
        substr($code, $data->{'sh_offset'}, $data->{'sh_size'})
    );

    poke(
        $rodata_ptr, 
        substr($code, $rodata->{'sh_offset'}, $rodata->{'sh_size'})
    );

    do_relocs($text_ptr, $data_ptr, $rodata_ptr, $jmptab_ptr);

    if(mprotect($text_ptr, $text->{'sh_size'}, 5) == -1) {
        print "Failed to mprotect .text\n";
        exit;
    }

    # check .rodata sh_size first in case is not defined
    if(exists $rodata->{'sh_size'}) {
        if(mprotect($rodata_ptr, $rodata->{'sh_size'}, 1) == -1) {
            print "Failed to mprotect .rodata\n";
            exit;
        }
    }

    if(mprotect($jmptab_ptr, $jmptab_size, 5) == -1) {
        print "Failed to mprotect jump table\n";
        exit;
    }

    # return pointer to start of the text segment
    # it will be used to calculate the pointer of the function to be executed
    return $text_ptr;
}

# execute mapped function (e.g. main)
sub exec_func {
    my $func_name   = shift;
    my $text_ptr    = shift;
    my $func_ptr    = $funcs{$func_name};

    my $func = DynaLoader::dl_install_xsub(
        "_japh", # not really used
        $text_ptr + $func_ptr, 
        __FILE__ # no file
    );

    # dereference and execute
    &{$func};
}


###############################################################################
# main
###############################################################################

my ($code, $fh) = read_elf();
parse_elf($fh);
my $text_ptr = map_elf($code);
exec_func('main', $text_ptr);


###############################################################################
# ELF binary content
###############################################################################

# hardcoded to achieve fd-less execution
# perl -e 'print"my \$code = \"\";\n";$/=\32;' \
# -e 'print"\$code .= pack q/H*/, q/".(unpack"H*")."/;\n" while(<>)' ./obj.o
#
# hardcoded C code:
# ----------------------- BEGIN obj.c ---------------------------------------
# #include <stdio.h>
# 
# void print_japh(void) {
#     putchar('j');
#     putchar('a');
#     putchar('p');
#     putchar('h');
#     putchar('\n');
# }
# 
# int main(void) {
#     char *str = "i am an elf";
# 
#     printf("%s\n", str);
#     print_japh();
# 
#     return 0;
# }
# ----------------------- END obj.c -----------------------------------------
#

sub get_code {
    my $code = "";
    $code .= pack q/H*/, q/7f454c4602010100000000000000000001003e00010000000000000000000000/;
    $code .= pack q/H*/, q/000000000000000018040000000000000000000040000000000040000d000c00/;
    $code .= pack q/H*/, q/554889e5bf6a000000e800000000bf61000000e800000000bf70000000e80000/;
    $code .= pack q/H*/, q/0000bf68000000e800000000bf0a000000e800000000905dc3554889e54883ec/;
    $code .= pack q/H*/, q/10488d0500000000488945f8488b45f84889c7e800000000e800000000b80000/;
    $code .= pack q/H*/, q/0000c9c36920616d20616e20656c6600004743433a202844656269616e203130/;
    $code .= pack q/H*/, q/2e322e312d36292031302e322e31203230323130313130001400000000000000/;
    $code .= pack q/H*/, q/017a5200017810011b0c0708900100001c0000001c0000000000000039000000/;
    $code .= pack q/H*/, q/00410e108602430d06740c07080000001c0000003c000000000000002b000000/;
    $code .= pack q/H*/, q/00410e108602430d06660c070800000000000000000000000000000000000000/;
    $code .= pack q/H*/, q/0000000000000000010000000400f1ff00000000000000000000000000000000/;
    $code .= pack q/H*/, q/0000000003000100000000000000000000000000000000000000000003000300/;
    $code .= pack q/H*/, q/0000000000000000000000000000000000000000030004000000000000000000/;
    $code .= pack q/H*/, q/0000000000000000000000000300050000000000000000000000000000000000/;
    $code .= pack q/H*/, q/0000000003000700000000000000000000000000000000000000000003000800/;
    $code .= pack q/H*/, q/0000000000000000000000000000000000000000030006000000000000000000/;
    $code .= pack q/H*/, q/0000000000000000070000001200010000000000000000003900000000000000/;
    $code .= pack q/H*/, q/1200000010000000000000000000000000000000000000002800000010000000/;
    $code .= pack q/H*/, q/0000000000000000000000000000000030000000120001003900000000000000/;
    $code .= pack q/H*/, q/2b00000000000000350000001000000000000000000000000000000000000000/;
    $code .= pack q/H*/, q/006f626a2e63007072696e745f6a617068005f474c4f42414c5f4f4646534554/;
    $code .= pack q/H*/, q/5f5441424c455f0070757463686172006d61696e007075747300000000000000/;
    $code .= pack q/H*/, q/0a00000000000000040000000b000000fcffffffffffffff1400000000000000/;
    $code .= pack q/H*/, q/040000000b000000fcffffffffffffff1e00000000000000040000000b000000/;
    $code .= pack q/H*/, q/fcffffffffffffff2800000000000000040000000b000000fcffffffffffffff/;
    $code .= pack q/H*/, q/3200000000000000040000000b000000fcffffffffffffff4400000000000000/;
    $code .= pack q/H*/, q/0200000005000000fcffffffffffffff5400000000000000040000000d000000/;
    $code .= pack q/H*/, q/fcffffffffffffff59000000000000000400000009000000fcffffffffffffff/;
    $code .= pack q/H*/, q/2000000000000000020000000200000000000000000000004000000000000000/;
    $code .= pack q/H*/, q/02000000020000003900000000000000002e73796d746162002e737472746162/;
    $code .= pack q/H*/, q/002e7368737472746162002e72656c612e74657874002e64617461002e627373/;
    $code .= pack q/H*/, q/002e726f64617461002e636f6d6d656e74002e6e6f74652e474e552d73746163/;
    $code .= pack q/H*/, q/6b002e72656c612e65685f6672616d6500000000000000000000000000000000/;
    $code .= pack q/H*/, q/0000000000000000000000000000000000000000000000000000000000000000/;
    $code .= pack q/H*/, q/0000000000000000000000000000000000000000000000002000000001000000/;
    $code .= pack q/H*/, q/0600000000000000000000000000000040000000000000006400000000000000/;
    $code .= pack q/H*/, q/0000000000000000010000000000000000000000000000001b00000004000000/;
    $code .= pack q/H*/, q/40000000000000000000000000000000c002000000000000c000000000000000/;
    $code .= pack q/H*/, q/0a00000001000000080000000000000018000000000000002600000001000000/;
    $code .= pack q/H*/, q/03000000000000000000000000000000a4000000000000000000000000000000/;
    $code .= pack q/H*/, q/0000000000000000010000000000000000000000000000002c00000008000000/;
    $code .= pack q/H*/, q/03000000000000000000000000000000a4000000000000000000000000000000/;
    $code .= pack q/H*/, q/0000000000000000010000000000000000000000000000003100000001000000/;
    $code .= pack q/H*/, q/02000000000000000000000000000000a4000000000000000c00000000000000/;
    $code .= pack q/H*/, q/0000000000000000010000000000000000000000000000003900000001000000/;
    $code .= pack q/H*/, q/30000000000000000000000000000000b0000000000000002800000000000000/;
    $code .= pack q/H*/, q/0000000000000000010000000000000001000000000000004200000001000000/;
    $code .= pack q/H*/, q/00000000000000000000000000000000d8000000000000000000000000000000/;
    $code .= pack q/H*/, q/0000000000000000010000000000000000000000000000005700000001000000/;
    $code .= pack q/H*/, q/02000000000000000000000000000000d8000000000000005800000000000000/;
    $code .= pack q/H*/, q/0000000000000000080000000000000000000000000000005200000004000000/;
    $code .= pack q/H*/, q/4000000000000000000000000000000080030000000000003000000000000000/;
    $code .= pack q/H*/, q/0a00000008000000080000000000000018000000000000000100000002000000/;
    $code .= pack q/H*/, q/0000000000000000000000000000000030010000000000005001000000000000/;
    $code .= pack q/H*/, q/0b00000009000000080000000000000018000000000000000900000003000000/;
    $code .= pack q/H*/, q/0000000000000000000000000000000080020000000000003a00000000000000/;
    $code .= pack q/H*/, q/0000000000000000010000000000000000000000000000001100000003000000/;
    $code .= pack q/H*/, q/00000000000000000000000000000000b0030000000000006100000000000000/;
    $code .= pack q/H*/, q/000000000000000001000000000000000000000000000000/;

    return $code;
}