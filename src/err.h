#ifndef LF_ERR_H_
#define LF_ERR_H_

#define LF_E_OK 0
#define LF_E_CORRUPT 1
#define LF_E_PASSWORD LF_E_CORRUPT
#define LF_E_EXIST 2
#define LF_E_NOTFOUND 3
#define LF_E_INVALID 4
#define LF_E_RANGE 5

#define LF_E_UNKNOWN 999

int LF_err_from_errno(int e);

#endif // !LF_ERR_H_
