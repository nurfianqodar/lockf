#include "cli.h"
#include "err.h"
#include <stdio.h>

int main(int argc, char **argv)
{
	LF_cli_config config;
	if (0 != LF_cli_config_parse(&config, argc, argv)) {
		LF_cli_print_usage();
		return 1;
	}
	if (-1 == LF_cli_run(&config)) {
		return 1;
	}
	return LF_E_OK;
}
