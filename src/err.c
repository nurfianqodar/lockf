#include "err.h"
#include <asm-generic/errno-base.h>

int LF_err_from_errno(int e)
{
	switch (e) {
	case ENOENT:
		return LF_E_NOTFOUND;
	case EEXIST:
		return LF_E_EXIST;
	case ENFILE:
	case EISDIR:
		return LF_E_NOTFILE;
	}

	return LF_E_UNKNOWN;
}
