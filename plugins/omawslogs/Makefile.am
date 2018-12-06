pkglib_LTLIBRARIES = omawslogs.la

omawslogs_la_SOURCES = omawslogs.c
omawslogs_la_CPPFLAGS = -I$(top_srcdir) $(PTHREADS_CFLAGS) $(RSRT_CFLAGS)
omawslogs_la_LDFLAGS = -module -avoid-version -laws-cpp-sdk-core -laws-cpp-sdk-logs -lrsyslog_awslib
