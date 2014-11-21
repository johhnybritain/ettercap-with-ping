#ifndef WINGETTIMEOFDAY_H
#define WINGETTIMEOFDAY_H
#include <windows.h>

#ifdef __cplusplus
extern "C"{
#endif
int gettimeofday(struct timeval* tp, void* tzp);
#ifdef __cplusplus
}
#endif

#endif
