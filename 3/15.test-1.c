/* warning: entirely throw-away code, no error checking, just PoC! */

#include <fcntl.h>
#include <io.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>

/* ELF header, 64-bit CPU */
static unsigned char string1[] = { 0x7f, 0x45, 0x4c, 0x46, 0x02 };
/* infection marker */
static unsigned char string2[] = { 0x54, 0x4d, 0x5a, 0x00 };
/* virus code snippet */
static unsigned char string3[] = { 0x48, 0x81, 0xEC, 0xD0, 0x07, 0x00, 0x00, 0x49, 0x89, 0xE7, 0x6A, 0x2E };

#define read16le(buffer, offset) (((unsigned int) buffer[(offset) + 1] << 8) + buffer[(offset)])
#define read64le(buffer, offset) (((unsigned __int64) buffer[(offset) + 7] << 56) + ((unsigned __int64) buffer[(offset) + 6] << 48) \
                                + ((unsigned __int64) buffer[(offset) + 5] << 40) + ((unsigned __int64) buffer[(offset) + 4] << 32) \
                                + ((unsigned int) buffer[(offset) + 3] << 24) + ((unsigned int) buffer[(offset) + 2] << 16) \
                                + ((unsigned int) buffer[(offset) + 1] << 8) + buffer[offset])
#define write32le(buffer, offset, value) buffer[(offset) + 3] = (unsigned char) ((unsigned int) (value) >> 24); \
                                         buffer[(offset) + 2] = (unsigned char) ((unsigned int) (value) >> 16); \
                                         buffer[(offset) + 1] = (unsigned char) ((unsigned int) (value) >> 8); \
                                         buffer[(offset)] = (unsigned char) (value);
#define write64le(buffer, offset, value) buffer[(offset) + 7] = (unsigned char) ((unsigned __int64) (value) >> 56); \
                                         buffer[(offset) + 6] = (unsigned char) ((unsigned __int64) (value) >> 48); \
                                         buffer[(offset) + 5] = (unsigned char) ((unsigned __int64) (value) >> 40); \
                                         buffer[(offset) + 4] = (unsigned char) ((unsigned __int64) (value) >> 32); \
                                         buffer[(offset) + 3] = (unsigned char) ((unsigned int) (value) >> 24); \
                                         buffer[(offset) + 2] = (unsigned char) ((unsigned int) (value) >> 16); \
                                         buffer[(offset) + 1] = (unsigned char) ((unsigned int) (value) >> 8); \
                                         buffer[(offset)] = (unsigned char) (value);

void main(int argc, char *argv[])
{
    int i;
    unsigned char buffer[0x40];

    #define ORGNAME argv[1]
    i = open(ORGNAME, O_RDONLY | O_BINARY);
    read(i, buffer, sizeof(buffer));

    /* ensure 64-bit ELF with infection marker, and AMD64 file format */
    if (!memcmp(buffer, string1, sizeof(string1))
     && !memcmp(buffer + 9, string2, sizeof(string2))
     && (0x3E == buffer[18]))
    {
        int offset;
        unsigned char code[sizeof(string3)];

        offset = read16le(buffer, 0x34);
        _lseek(i, offset, SEEK_SET);
        read(i, code, sizeof(code));

        /* check for virus code, since we leave the infection marker behind on disinfection, as innoculation */
        if (!memcmp(code, string3, sizeof(string3)))
        {
            int o;
            unsigned __int64 phoff, shoff, bytesleft;
            int phnum, shnum;
            unsigned char *tmp;

            #define COPYNAME "out"
            o = open(COPYNAME, O_WRONLY | O_BINARY | O_CREAT | O_TRUNC, 0x80);

            /* write partial ELF header, with infection marker, since it was an irreversible change anyway */
            write32le(buffer, 9, 0);

            phoff = read64le(buffer, 0x20);
            shoff = read64le(buffer, 0x28);
            phnum = read16le(buffer, 0x38);
            shnum = read16le(buffer, 0x3c);

            /* shrink phoff and shoff sizes according to virus size */
            write64le(buffer, 0x20, phoff - 0x1000);
            write64le(buffer, 0x28, shoff - 0x1000);
            /* restore original entrypoint */
            _lseek(i, 0x420, SEEK_SET);
            write64le(buffer, 0x18, 0);
            read(i, buffer + 0x18, 4);
            write(o, buffer, sizeof(buffer));

            _lseeki64(i, phoff, SEEK_SET);
            _lseeki64(o, phoff - 0x1000, SEEK_SET);
            /* limit read size rather than reading the entire file in one pass */
            #define TMPSIZE 0x10000
            tmp = (unsigned char *) malloc(TMPSIZE);

            do
            {
                __int64 curposi, curposo, offset, size;

                /* read program header entry */
                read(i, buffer, 0x38);
                curposi = tell(i);
                offset = read64le(buffer, 8);
                size = read64le(buffer, 32);
                /* move to corresponding segment */
                _lseeki64(i, offset, SEEK_SET);

                /* check for loadable, executable, readable */
                if ((1 == buffer[0])
                 && (5 == buffer[4]))
                {
                    /* adjust segment attributes to reverse changes that the virus made */
                    offset += 0x1000;
                    size -= 0x2000;
                    _lseeki64(i, offset + 0x1000, SEEK_SET);
                    write64le(buffer, 8, offset);
                    write64le(buffer, 16, read64le(buffer, 16) + 0x2000);
                    write64le(buffer, 32, size);
                    write64le(buffer, 40, read64le(buffer, 40) - 0x2000);
                }
                else
                {
                    /* adjust segment attributes to reverse changes that the virus made */
                    offset -= 0x1000;
                    write64le(buffer, 8, offset);
                }

                write(o, buffer, 0x38);

                /* if program header is not the ELF header */
                if (offset && (0x40 != offset))
                {
                    /* move file content back to original location to remove virus body */
                    curposo = tell(o);
                    _lseeki64(o, offset, SEEK_SET);
                    /* max TMPSIZE bytes at a time */
                    do {} while (0 != (size -= write(o, tmp, read(i, tmp, (size > TMPSIZE) ? TMPSIZE : size))));
                    _lseeki64(o, curposo, SEEK_SET);
                }

                _lseeki64(i, curposi, SEEK_SET);
            }
            while (--phnum);

            /* now for the section headers */
            _lseeki64(i, shoff, SEEK_SET);
            _lseeki64(o, shoff - 0x1000, SEEK_SET);

            do
            {
                unsigned __int64 curposi, curposo, offset, size;

                /* adjust section sizes to reverse changes that the virus made */
                read(i, buffer, sizeof(buffer));
                curposi = tell(i);
                offset = read64le(buffer, 24);
                size = read64le(buffer, 32);
                _lseeki64(i, offset, SEEK_SET);
                offset -= 0x1000;
                write64le(buffer, 24, offset);
                write(o, buffer, sizeof(buffer));

                /* if section is loaded */
                if (offset)
                {
                    /* move file content back to original location to remove virus body */
                    curposo = tell(o);
                    _lseeki64(o, offset, SEEK_SET);
                    /* max TMPSIZE bytes at a time */
                    do {} while (0 != (size -= write(o, tmp, read(i, tmp, (size > TMPSIZE) ? TMPSIZE : size))));
                    _lseeki64(o, curposo, SEEK_SET);
                }

                _lseeki64(i, curposi, SEEK_SET);
            }
            while (--shnum);

            free(tmp);
            close(o);
        }
    }

    close(i);
}
