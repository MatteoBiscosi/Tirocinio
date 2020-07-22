/*
 *
 * Source code copied from ntop.org
 * (C) 2013-20 - ntop.org
 *
 */

#ifndef _TRACE_H_
#define _TRACE_H_

#include "ndpi_light_includes.h"


#ifndef MAX_PATH
#define MAX_PATH                  256
#endif

#define TRACE_LEVEL_ERROR     0
#define TRACE_LEVEL_WARNING   1
#define TRACE_LEVEL_NORMAL    2
#define TRACE_LEVEL_INFO      3
#define TRACE_LEVEL_DEBUG     6
#define TRACE_LEVEL_TRACE     9

#define TRACE_ERROR     TRACE_LEVEL_ERROR, __FILE__, __LINE__
#define TRACE_WARNING   TRACE_LEVEL_WARNING, __FILE__, __LINE__
#define TRACE_NORMAL    TRACE_LEVEL_NORMAL, __FILE__, __LINE__
#define TRACE_INFO      TRACE_LEVEL_INFO, __FILE__, __LINE__
#define TRACE_DEBUG     TRACE_LEVEL_DEBUG, __FILE__, __LINE__
#define TRACE_TRACE     TRACE_LEVEL_TRACE, __FILE__, __LINE__

#define MAX_TRACE_LEVEL 9
#define TRACE_DEBUGGING MAX_TRACE_LEVEL

#define TRACES_PER_LOG_FILE_HIGH_WATERMARK 10000
#define MAX_NUM_NTOPNG_LOG_FILES           5
#define MAX_NUM_NTOPNG_TRACES              32
#define CONST_DEFAULT_FILE_MODE      0600 /* rw */



/* ******************************* */

class Trace {
 private:
  char *logFile;
  FILE *logFd;
  int numLogLines = 0;
  volatile u_int8_t traceLevel = 0;
  pthread_mutex_t the_mutex;

private:
  void open_log();
#ifdef WIN32
  void AddToMessageLog(LPTSTR lpszMsg);
#endif

 public:
  Trace();
  ~Trace();

  void rotate_logs(bool forceRotation);
  void set_log_file(const char *log_file);
  void set_trace_level(u_int8_t id);
  inline u_int8_t get_trace_level() { return(traceLevel); };
  void traceEvent(int eventTraceLevel, const char * format, ...);
};


#endif /* _TRACE_H_ */