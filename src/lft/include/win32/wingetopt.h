#ifndef WINGETOPT_H
#define WINGETOPT_H

#ifdef __cplusplus
extern "C"{
#endif
extern int optind, opterr;
extern char *optarg;

int getopt(int argc, char *argv[], char *optstring);
#ifdef __cplusplus
}
#endif

#endif
