#ifndef LOG_H_
#define LOG_H_

#include <stdarg.h>

#ifndef LOG_DOMAIN
#define LOG_DOMAIN ((char *) 0)
#endif

typedef enum
{
  LOG_LEVEL_ERROR	= 1 << 0, /* causes a call to abort() */
  LOG_LEVEL_WARNING	= 1 << 1,
  LOG_LEVEL_MESSAGE	= 1 << 2,
  LOG_LEVEL_NOTICE	= 1 << 3,
  LOG_LEVEL_DEBUG	= 1 << 4,
} log_level_t;

typedef void (*log_fn) (const char * program, const char * domain,
                        log_level_t level,
			const char * message, struct timeval tv,
			void * user_data);

log_level_t log_get_level ();
void        log_set_level (log_level_t level);

void log_set_handler (const char * domain, log_fn user_fn,
		      void * user_data);

void log_set_program (const char * program);
void log_set_use_color (int use_color);

void log_out  (const char * domain, log_level_t level,
	       const char * format, ...);

void log_outv (const char * domain, log_level_t level,
	       const char * format, va_list args);

char * log_level_name (log_level_t level);

#ifdef LOG_DISABLE

#define error(args...)  log_last_level = LOG_LEVEL_ERROR
#define warn(args...)   log_last_level = LOG_LEVEL_WARNING
#define msg(args...)    log_last_level = LOG_LEVEL_MESSAGE
#define notice(args...) log_last_level = LOG_LEVEL_NOTICE

#else

#define error(args...) \
log_out(LOG_DOMAIN, LOG_LEVEL_ERROR, args)

#define debug(args...) \
log_out(LOG_DOMAIN, LOG_LEVEL_DEBUG, args)

#define warn(args...) \
log_out(LOG_DOMAIN, LOG_LEVEL_WARNING, args)

#define msg(args...) \
log_out(LOG_DOMAIN, LOG_LEVEL_MESSAGE, args)

#define notice(args...) \
log_out(LOG_DOMAIN, LOG_LEVEL_NOTICE, args)

#endif

#if defined(LOG_DISABLE) || !defined(DEBUG)

#define debug(args...)  log_last_level = LOG_LEVEL_DEBUG

#else

#define debug(args...) \
log_out(LOG_DOMAIN, LOG_LEVEL_DEBUG, args)

#endif

#if defined(LOG_DISABLE) || !defined(DEBUG)
extern int log_last_level;
#endif

#endif /*LOG_H_*/
