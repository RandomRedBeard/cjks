#ifndef CJKS_ERR_H
#define CJKS_ERR_H

#ifdef _WIN32
#define cjks_thread __declspec(thread)
#else
#define cjks_thread __thread
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <cjks/lib.h>

#define CJKS_ERRNO_FLAG (1 << '\x00')
#define CJKS_IO_ERR (1 << '\x01')

CJKS_DLL void cjks_set_errno();

#endif