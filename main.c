#include "winpe.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <err.h>
#include <getopt.h>

int main(int argc, char **argv)
{
   if (argc < 2) {
      LOG("No PE files passed to be checked");
      return EXIT_FAILURE;
   }
   struct option opts[] = {
       { "verbose", no_argument, NULL, 'v' },
       { "no-verbose", no_argument, NULL, 'V' },
       { "help", no_argument, NULL, 'h' },
       { NULL, 0, NULL, 0 },
   };
   bool verbose = false;
   for (;;) {
      int index;
      int v = getopt_long(argc, argv, "+", opts, &index);
      switch (v) {
         case ':':
         case '?':
            return EXIT_FAILURE;
         case 'v':
            verbose = true;
            break;
         case 'V':
            verbose = false;
            break;
         case 'h':
            fputs("Usage: pechk [--verbose] [--no-verbose] [--] FILE [FILES...]\n", stdout);
            if (fflush(NULL) || ferror(stdout))
               errx(1, "I/O error on stdout");
            return 0;
         case -1:
            goto end_of_options;
         default:
            assert(0);
            return EXIT_FAILURE;
      }
   }
end_of_options:
   for (int i = optind; i < argc; ++i) {
      struct stat buf;
      int p = open(argv[i], O_RDONLY | O_CLOEXEC | O_NOCTTY);
      if (p < 0)
         err(EXIT_FAILURE, "open(%s)", argv[i]);
      if (fstat(p, &buf))
         err(EXIT_FAILURE, "fstat(%s)", argv[i]);
      if (buf.st_size > 0x7FFFFFFFL || buf.st_size < 0)
         errx(EXIT_FAILURE, "file %s too long", argv[i]);
      size_t size = (size_t)buf.st_size;
      uint8_t *fbuf = malloc(size);
      if (!fbuf)
         err(1, "malloc(%zu)", size);
      size_t data_read = 0;
      while (data_read < size) {
          ssize_t bytes_read = read(p, fbuf + data_read, size - data_read);
          if (bytes_read < 0) {
              if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                  continue;
              err(1, "read");
          }
          data_read += (size_t)bytes_read;
      }
      struct ParsedImage image;
      if (!pe_parse(fbuf, size, &image, verbose))
         errx(1, "bad PE file");
      if (fflush(NULL) || ferror(stdout) || ferror(stderr))
         errx(1, "I/O error");
      free(fbuf);
      close(p);
   }
}
