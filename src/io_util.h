#ifndef LF_IO_UTIL_H_
#define LF_IO_UTIL_H_

#include <stddef.h>
#include <stdint.h>

int LF_io_open_read(int *fd, const char *path);

int LF_io_open_wirte(int *fd, const char *path, bool trunc);

int LF_io_close(int *fd);

int LF_io_read_max_or_eof(int fd, void *out, size_t *out_len, size_t max);

int LF_io_read_exact(int fd, void *out, size_t out_len);

int LF_io_write_exact(int fd, const void *in, size_t in_len);

int LF_io_write_u32(int fd, const uint32_t *in, int ord);

int LF_io_read_u32(int fd, uint32_t *out, int ord);

#endif
