#ifndef MOOR_EXIT_NOTICE_H
#define MOOR_EXIT_NOTICE_H

/* Exit-notice HTTP server: binds 0.0.0.0:80 and serves a static page
 * explaining that the IP is a MOOR exit relay. Skips silently if port 80
 * is already in use or bind fails (EACCES without CAP_NET_BIND_SERVICE).
 * Safe to call multiple times — only the first call binds.
 *
 * Returns 0 on success (listening), -1 on failure (silent skip). */
int moor_exit_notice_start(const char *nickname,
                           const char *contact_info,
                           const char *build_id);

#endif /* MOOR_EXIT_NOTICE_H */
