#include "cli.h"
#include "chunk.h"
#include "err.h"
#include "header.h"
#include "io_util.h"
#include "key.h"
#include <linux/limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

static int strtou32(const char *s, uint32_t *out)
{
	if (!s || !out) {
		return LF_E_INVALID;
	}
	errno = 0;
	char *end = NULL;
	unsigned long val = strtoul(s, &end, 10);
	if (end == s) {
		return LF_E_INVALID;
	}
	if ('\0' != *end) {
		return LF_E_INVALID;
	}
	if (ERANGE == errno) {
		return LF_E_RANGE;
	}
	if (val > UINT32_MAX) {
		return LF_E_RANGE;
	}
	*out = (uint32_t)val;
	return LF_E_OK;
}

static int cli_run(const LF_cli_config *config, int fd_in, int fd_out)
{
	int ret;
	LF_header header;
	switch (config->mode) {
	case LF_CLIMODE_ENCRYPT:
		ret = LF_header_new(&header, config->time_cost,
				    config->memory_cost, config->parallelism);
		if (ret != 0) {
			printf("unable to create header\n");
			return ret;
		}
		ret = LF_header_write(&header, fd_out);
		if (ret != 0) {
			return ret;
		}
		break;
	case LF_CLIMODE_DECRYPT:
		ret = LF_header_read(&header, fd_in);
		if (ret != 0) {
			return ret;
		}
		break;
	default:
		return LF_E_INVALID;
	}

	LF_key key;
	ret = LF_key_new(&key, &header, config->pwd, config->pwd_len);
	if (ret != 0) {
		return ret;
	}

	LF_chunk chunk;
	LF_chunk_mode chunk_mode;
	switch (config->mode) {
	case LF_CLIMODE_ENCRYPT:
		chunk_mode = LF_CMODE_PLAIN;
		break;
	case LF_CLIMODE_DECRYPT:
		chunk_mode = LF_CMODE_CIPHER;
		break;
	default:
		return LF_E_INVALID;
	}

	do {
		ret = LF_chunk_read(&chunk, fd_in, chunk_mode);
		if (0 != ret) {
			return ret;
		}
		switch (config->mode) {
		case LF_CLIMODE_ENCRYPT:
			ret = LF_chunk_encrypt(&chunk, &header, &key);
			if (0 != ret) {
				return ret;
			}
			break;
		case LF_CLIMODE_DECRYPT:
			ret = LF_chunk_decrypt(&chunk, &header, &key);
			if (0 != ret) {
				return ret;
			}
			break;
		default:
			return LF_E_INVALID;
		}
		ret = LF_chunk_write(&chunk, fd_out);
		if (0 != ret) {
			return ret;
		}
	} while (chunk.buf_len == LF_CHK_BUF_LEN_MAX);
	return LF_E_OK;
}

struct option OPTS[] = {
	{ "help", no_argument, 0, 'h' },
	{ "input", required_argument, 0, 'i' },
	{ "output", required_argument, 0, 'o' },
	{ "password", required_argument, 0, 'P' },
	{ "time", required_argument, 0, 't' },
	{ "memory", required_argument, 0, 'm' },
	{ "parallelism", required_argument, 0, 'p' },
	{ 0, 0, 0, 0 },
};

int LF_cli_config_parse(LF_cli_config *config, int argc, char **argv)
{
	if (argc < 2) {
		return LF_E_NOOP;
	}
	const char *mode = argv[1];
	if (0 == strcmp(mode, "h") || 0 == strcmp(mode, "help")) {
		return LF_E_NOOP;
	} else if (0 == strcmp(mode, "e") || 0 == strcmp(mode, "encrypt")) {
		config->mode = LF_CLIMODE_ENCRYPT;
	} else if (0 == strcmp(mode, "d") || 0 == strcmp(mode, "decrypt")) {
		config->mode = LF_CLIMODE_DECRYPT;
	} else {
		LF_cli_print_usage();
		return LF_E_INVALID;
	}

	bool has_i, has_o, has_P, has_t, has_m, has_p;
	has_i = has_o = has_P = has_t = has_m = has_p = false;
	optind = 2;
	int opt;
	while (-1 !=
	       (opt = getopt_long(argc, argv, "i:o:P:t:m:p:", OPTS, NULL))) {
		switch (opt) {
		case 'i':
			snprintf(config->input_path, PATH_MAX, "%s", optarg);
			has_i = true;
			break;
		case 'o':
			snprintf(config->output_path, PATH_MAX, "%s", optarg);
			has_o = true;
			break;
		case 'P':
			config->pwd_len = strlen(optarg);
			if (config->pwd_len >= LF_CLI_PWD_MAX) {
				return LF_E_INVALID;
			}
			memcpy(config->pwd, optarg, config->pwd_len);
			has_P = true;
			break;
		case 't':
			if (0 != strtou32(optarg, &config->time_cost)) {
				return LF_E_INVALID;
			}
			has_t = true;
			break;
		case 'm':
			if (0 != strtou32(optarg, &config->memory_cost)) {
				return LF_E_INVALID;
			}
			has_m = true;
			break;
		case 'p':
			if (0 != strtou32(optarg, &config->parallelism)) {
				return LF_E_INVALID;
			}
			has_p = true;
			break;
		}
	}
	if (!(has_i && has_o && has_P)) {
		return LF_E_NOARGS;
	}
	if (!has_t) {
		config->time_cost = LF_CLI_TIME_COST_DEFAULT;
	}
	if (!has_m) {
		config->memory_cost = LF_CLI_MEMORY_COST_DEFAULT;
	}
	if (!has_p) {
		config->parallelism = LF_CLI_PARALLELISM_DEFAULT;
	}
	return LF_E_OK;
}

int LF_cli_config_validate(const LF_cli_config *config)
{
	(void)config;
	return LF_E_OK;
}

int LF_cli_run(const LF_cli_config *config)
{
	int fd_in, fd_out;
	int ret;
	ret = LF_io_open_read(&fd_in, config->input_path);
	if (0 != ret) {
		return ret;
	}
	ret = LF_io_open_wirte(&fd_out, config->output_path, false);
	if (0 != ret) {
		LF_io_close(&fd_in);
		return ret;
	}
	ret = cli_run(config, fd_in, fd_out);

	if (0 != ret) {
		LF_io_close(&fd_in);
		LF_io_close(&fd_out);
		remove(config->output_path);
		return ret;
	}
	return LF_E_OK;
}

static const char *USAGE = "Usage:\n"
			   "lockf <MODE> <OPTIONS> <VALUE> ...\n"
			   "MODE:\n"
			   "\te: encrypt\n"
			   "\td: decrypt\n"
			   "\th: help\n"
			   "\nOPTIONS:\n"
			   "\t-i: input file,\t\tvalue: path,\trequired\n"
			   "\t-o: output file,\tvalue: path,\trequired\n"
			   "\t-P: password,\t\tvalue: string,\trequired\n"
			   "\t-t: time cost,\t\tvalue: uint32,\toptional\n"
			   "\t-m: memory cost,\tvalue: uint32,\toptional\n"
			   "\t-p: parallelism,\tvalue: uint32,\toptional\n";

void LF_cli_print_usage(void)
{
	printf("%s", USAGE);
}
