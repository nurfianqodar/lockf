#include "cli.h"
#include "err.h"
#include <stdio.h>

int main(int argc, char **argv)
{
	LF_cli_config config;
	int ret;
	if (0 != (ret = LF_cli_config_parse(&config, argc, argv))) {
		switch (ret) {
		case LF_E_NOARGS:
		case LF_E_INVALID:
			fprintf(stderr, "invalid arguments\n");
			LF_cli_print_usage();
			break;
		case LF_E_RANGE:
			fprintf(stderr, "value is too large\n");
			break;
		case LF_E_NOOP:
			LF_cli_print_usage();
			return 0;
		}

		return 1;
	}
	if (0 != (ret = LF_cli_run(&config))) {
		switch (ret) {
		case LF_E_CORRUPT:
			fprintf(stderr, "invalid password or file corrupt\n");
			break;
		case LF_E_EXIST:
			fprintf(stderr,
				"unable to create file: alredy exists\n");
			break;
		default:
			fprintf(stderr, "unknown error\n");
		}
		return ret;
	}
	return LF_E_OK;
}
