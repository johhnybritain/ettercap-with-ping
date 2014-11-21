#if defined(WIN32) || defined(_WIN32)

#include "wingettimeofday.h"
#include <sys/timeb.h>

#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif


int __gettimeofday(struct timeval* tv, void * tz) 
{
    struct _timeb currSysTime;
	_ftime(&currSysTime);
	
	tv->tv_sec = currSysTime.time;
	tv->tv_usec = currSysTime.millitm * 1000;

    return 0;
}

LARGE_INTEGER getFILETIMEoffset()
{
	SYSTEMTIME s;
	FILETIME f;
	LARGE_INTEGER t;

	s.wYear = 1970;
	s.wMonth = 1;
	s.wDay = 1;
	s.wHour = 0;
	s.wMinute = 0;
	s.wSecond = 0;
	s.wMilliseconds = 0;
	SystemTimeToFileTime(&s, &f);
	t.QuadPart = f.dwHighDateTime;
	t.QuadPart <<= 32;
	t.QuadPart |= f.dwLowDateTime;
	return (t);
}

int gettimeofday(struct timeval *tv, void * tz)
{
	LARGE_INTEGER   t;
	FILETIME   f;
	double     microseconds;
	static LARGE_INTEGER offset;
	static LARGE_INTEGER base;
	static double   frequencyToMicroseconds;
	static int    initialized = 0;
	static BOOL    usePerformanceCounter = 0;

	if(!initialized)
	{
		LARGE_INTEGER performanceFrequency;
		initialized = 1;
		usePerformanceCounter = QueryPerformanceFrequency(&performanceFrequency);
		if(usePerformanceCounter)
		{
			LARGE_INTEGER tmpoffs;
			QueryPerformanceCounter(&offset);
			frequencyToMicroseconds = (double)performanceFrequency.QuadPart / 1000000.;

			tmpoffs = getFILETIMEoffset();
			GetSystemTimeAsFileTime(&f);
			base.QuadPart = f.dwHighDateTime;
			base.QuadPart <<= 32;
			base.QuadPart |= f.dwLowDateTime;
			base.QuadPart -= tmpoffs.QuadPart;
			microseconds = (double)base.QuadPart / 10;
			base.QuadPart = microseconds;
	tv->tv_sec = base.QuadPart / 1000000;
	tv->tv_usec = base.QuadPart % 1000000;
		}
		else
		{
			offset = getFILETIMEoffset();
			frequencyToMicroseconds = 10.;
			base.QuadPart=0i64;
		}
	}
	if(usePerformanceCounter)
		QueryPerformanceCounter(&t);
	else
	{
		GetSystemTimeAsFileTime(&f);
		t.QuadPart = f.dwHighDateTime;
		t.QuadPart <<= 32;
		t.QuadPart |= f.dwLowDateTime;
	}

	t.QuadPart -= offset.QuadPart;
	microseconds = (double)t.QuadPart / frequencyToMicroseconds;
	t.QuadPart = microseconds + base.QuadPart;
	tv->tv_sec = t.QuadPart / 1000000;
	tv->tv_usec = t.QuadPart % 1000000;
	return (0);
}

#endif
