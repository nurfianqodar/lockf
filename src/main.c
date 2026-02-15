#include "header.h"
#include "io_util.h"
#include "chunk.h"
#include "key.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>

int main()
{
	const char *pwd = "secretpassword";
	const size_t pwd_len = strlen(pwd);

	LF_header header;
	if (0 != LF_header_new(&header, 4, 1024 * 128, 2)) {
		return 1;
	}

	LF_key key;
	if (0 != LF_key_new(&key, &header, (const uint8_t *)pwd, pwd_len)) {
		return 1;
	}

	int plain_fd;

	if (LF_io_open_read(
		    &plain_fd,
		    "/home/fynn/Videos/go/struct_perf_bottle_neck.mp4")) {
		perror("open read error");
		return 1;
	}

	LF_chunk plain_chunk;

	int ret;
	do {
		ret = LF_chunk_read(&plain_chunk, plain_fd, LF_CMODE_PLAIN);
		if (ret != 0) {
			LF_io_close(&plain_fd);
			return 1;
		}
		printf("Len  = %d\n", plain_chunk.buf_len);
		printf("Mode = %d\n", plain_chunk.mode);

		ret = LF_chunk_encrypt(&plain_chunk, &header, &key);
		if (ret != 0) {
			LF_io_close(&plain_fd);
			return 1;
		}
		printf("Len  = %d\n", plain_chunk.buf_len);
		printf("Mode = %d\n", plain_chunk.mode);

		ret = LF_chunk_decrypt(&plain_chunk, &header, &key);
		if (ret != 0) {
			printf("decrypt error");
			LF_io_close(&plain_fd);
			return 1;
		}
		printf("Len  = %d\n", plain_chunk.buf_len);
		printf("Mode = %d\n", plain_chunk.mode);

		printf("=====================\n");

	} while (LF_CHK_BUF_LEN_MAX == plain_chunk.buf_len);

	LF_io_close(&plain_fd);
	return 0;
}
