/*
 *
 * Source code copied from ntop.org
 * (C) 2013-20 - ntop.org
 *
 */

#include "ndpi_light_includes.h"


/* ******************************* */

bool inline file_exists(const char *path) {
  std::ifstream infile(path);

  /*  ntop->getTrace()->traceEvent(TRACE_WARNING, "%s(): %s", __FUNCTION__, path); */
  bool ret = infile.good();
  infile.close();
  return ret;
}

/* ******************************* */

Trace::Trace() {
  traceLevel = TRACE_LEVEL_NORMAL;
  logFile = (char *) "./logs/log";
  logFd = NULL;
  pthread_mutex_init(&the_mutex, NULL);

  if(file_exists(logFile))
    open_log();
  else {
    open_log();
  }
};

/* ******************************* */

Trace::~Trace() {
  if(this->logFd)      fclose(logFd);
  
  pthread_mutex_destroy(&the_mutex);
};

/* ******************************* */

void Trace::rotate_logs(bool forceRotation) {
  char buf1[MAX_PATH], buf2[MAX_PATH];
  const int max_num_lines = TRACES_PER_LOG_FILE_HIGH_WATERMARK;

  if(!logFd) return;
  else if((!forceRotation) && (numLogLines < max_num_lines)) return;

  fclose(logFd);
  logFd = NULL;

  for(int i = MAX_NUM_NTOPNG_LOG_FILES - 1; i >= 1; i--) {
    snprintf(buf1, sizeof(buf1), "%s.%u", logFile, i);
    snprintf(buf2, sizeof(buf2), "%s.%u", logFile, i + 1);

    if(file_exists(buf1))
      rename(buf1, buf2);
  } /* for */

  if(file_exists(logFile)) {
    snprintf(buf1, sizeof(buf1), "%s.1", logFile);
    rename(logFile, buf1);
  }

  open_log();
}

/* ******************************* */

void Trace::open_log() {
  if(logFile) {
    logFd = fopen(logFile, "a");

    if(!logFd)
      traceEvent(TRACE_ERROR, "Unable to create log %s", logFile);
    else
      chmod(logFile, CONST_DEFAULT_FILE_MODE);
	    
    numLogLines = 0;
  }
}

/* ******************************* */

void Trace::set_log_file(const char* log_file) {
  if(log_file && log_file[0] != '\0') {
    rotate_logs(true);
    if(logFile) free(logFile);
    logFile = strndup(log_file, MAX_PATH);
    open_log();
  }
}

/* ******************************* */

void Trace::set_trace_level(u_int8_t id) {
  if(id > MAX_TRACE_LEVEL) id = MAX_TRACE_LEVEL;

  traceLevel = id;
}

/* ******************************* */

void Trace::traceEvent(int eventTraceLevel, const char * format, ...) {
  va_list va_ap;
#ifndef WIN32
  struct tm result;
#endif

  this->traceLevel;
  int line = this->numLogLines;

  if((eventTraceLevel <= this->traceLevel) && (this->traceLevel > 0)) {
    char buf[8100], out_buf[8192];
    char theDate[32], *file = this->logFile;
    const char *extra_msg = "";
    time_t theTime = time(NULL);
#ifndef WIN32
    char *syslogMsg;
#endif
    char filebuf[MAX_PATH];
    const char *backslash = strrchr(this->logFile,
#ifdef WIN32
				    '\\'
#else
				    '/'
#endif
				    );

    if(backslash != NULL) {
      snprintf(filebuf, sizeof(filebuf), "%s", &backslash[1]);
      file = (char*)filebuf;
    }

    va_start (va_ap, format);

    /* We have two paths - one if we're logging, one if we aren't
     *   Note that the no-log case is those systems which don't support it (WIN32),
     *                                those without the headers !defined(USE_SYSLOG)
     *                                those where it's parametrically off...
     */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime, &result));

    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    if(eventTraceLevel == 0 /* TRACE_ERROR */)
      extra_msg = "\tERROR: ";
    else if(eventTraceLevel == 1 /* TRACE_WARNING */)
      extra_msg = "\tWARNING: ";

    while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

    snprintf(out_buf, sizeof(out_buf), "%s [%s:%d] %s%s", theDate, file, line, extra_msg, buf) < 0 ? abort() : (void)0;

    if(logFd) {
      pthread_mutex_lock(&the_mutex);
      numLogLines++;
      fprintf(logFd, "%s\n", out_buf);
      fflush(logFd);
      rotate_logs(false);
      pthread_mutex_unlock(&the_mutex);
    } else {
#ifdef WIN32
      AddToMessageLog(out_buf);
#else
      syslogMsg = &out_buf[strlen(theDate)+1];
      if(eventTraceLevel == 0 /* TRACE_ERROR */)
	syslog(LOG_ERR, "%s", syslogMsg);
      else if(eventTraceLevel == 1 /* TRACE_WARNING */)
	syslog(LOG_WARNING, "%s", syslogMsg);
#endif
    }

    printf("%s\n", out_buf);
    fflush(stdout);

    va_end(va_ap);
  }
}

/* ******************************* */

#ifdef WIN32

/* service_win32.cpp */
extern "C" {
  extern short isWinNT();
  extern BOOL  bConsole;
};

/* ******************************* */

void Trace::AddToMessageLog(LPTSTR lpszMsg) {
  HANDLE  hEventSource;
  TCHAR	szMsg[4096];

#ifdef UNICODE
  LPCWSTR lpszStrings[1];
#else
  LPCSTR  lpszStrings[1];
#endif

  if(!isWinNT()) {
    char *msg = (char*)lpszMsg;
    printf("%s", msg);
    if(msg[strlen(msg)-1] != '\n')
      printf("\n");
    return;
  }

  if(!szMsg) {
    hEventSource = RegisterEventSource(NULL, TEXT(SZSERVICENAME));

    snprintf(szMsg, sizeof(szMsg), TEXT("%s: %s"), SZSERVICENAME, lpszMsg);

    lpszStrings[0] = szMsg;

    if (hEventSource != NULL) {
      ReportEvent(hEventSource,
		  EVENTLOG_INFORMATION_TYPE,
		  0,
		  EVENT_GENERIC_INFORMATION,
		  NULL,
		  1,
		  0,
		  lpszStrings,
		  NULL);

      DeregisterEventSource(hEventSource);
    }
  }
}

/* ******************************* */

#endif /* WIN32 */