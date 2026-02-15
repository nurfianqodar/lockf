#ifndef LF_IO_UTIL_H_
#define LF_IO_UTIL_H_

#include <stddef.h>

int LF_io_open_read(int *fd, const char *path);

int LF_io_open_wirte(int *fd, const char *path, bool trunc);

int LF_io_close(int *fd);

int LF_io_read_max_or_eof(int fd, void *out, size_t *out_len, size_t max);

int LF_io_read_exact(int fd, void *out, size_t out_len);

int LF_io_write_exact(int fd, const void *in, size_t in_len);

#endif
