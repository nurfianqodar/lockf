#include "io_util.h"
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

int LF_io_open_read(int *fd, const char *path)
{
	*fd = open(path, O_RDONLY | O_CLOEXEC);
	if (-1 == *fd) {
		return -errno;
	}
	return 0;
}

int LF_io_open_wirte(int *fd, const char *path, bool trunc)
{
	int oflag = O_WRONLY | O_CREAT | O_CLOEXEC;
	if (trunc) {
		oflag |= O_TRUNC;
	} else {
		oflag |= O_EXCL;
	}
	*fd = open(path, oflag, 0644);
	if (-1 == *fd) {
		return -errno;
	}
	return 0;
}

int LF_io_close(int *fd)
{
	if (-1 == close(*fd)) {
		return -errno;
	}
	return 0;
}

int LF_io_read_max_or_eof(int fd, void *out, size_t *out_len, size_t max)
{
	*out_len = 0;
	ssize_t n;
	while (*out_len < max) {
		n = read(fd, (uint8_t *)out + *out_len, max - *out_len);
		if (-1 == n) {
			if (EINTR == errno) {
				continue;
			}
			return -errno;
		}
		if (0 == n) {
			break;
		}
		*out_len += (size_t)n;
	}
	return 0;
}

int LF_io_read_exact(int fd, void *out, size_t out_len)
{
	size_t _out_len;
	int ret;
	if (0 != (ret = LF_io_read_max_or_eof(fd, out, &_out_len, out_len))) {
		return ret;
	}
	if (_out_len < out_len) {
		return -ENODATA;
	}
	if (_out_len > out_len) { // I think this is redundant
		return -EOVERFLOW;
	}
	return 0;
}

int LF_io_write_exact(int fd, const void *in, size_t in_len)
{
	size_t writen = 0;
	ssize_t n;

	while (writen < in_len) {
		n = write(fd, (uint8_t *)in, in_len - writen);
		if (-1 == n) {
			if (EINTR == errno) {
				continue;
			}
			return -errno;
		}
		if (0 == n) {
			return -ENODATA;
		}
		writen += (size_t)n;
	}
	return 0;
}

int LF_io_write_u32(int fd, const uint32_t *in, int ord)
{
	int ret;
	uint32_t ord_in;
	switch (ord) {
	case LITTLE_ENDIAN:
		ord_in = htole32(*in);
		break;
	case BIG_ENDIAN:
		ord_in = htobe32(*in);
	}

	ret = LF_io_write_exact(fd, &ord_in, 4);
	if (0 != ret) {
		return ret;
	}
	return 0;
}

int LF_io_read_u32(int fd, uint32_t *out, int ord)
{
	int ret;
	uint32_t ord_out;
	ret = LF_io_read_exact(fd, &ord_out, 4);
	if (0 != ret) {
		return ret;
	}
	switch (ord) {
	case LITTLE_ENDIAN:
		*out = le32toh(ord_out);
		break;
	case BIG_ENDIAN:
		*out = be32toh(ord_out);
		break;
	}
	return 0;
}
