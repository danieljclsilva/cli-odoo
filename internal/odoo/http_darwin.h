#include <stddef.h>

void *odoo_http_start(const char *url, const char *method, const char *headers,
                     const void *body, size_t length, double timeout,
                     size_t response_limit, int verify_tls);
int odoo_http_finished(void *handle);
char *odoo_http_metadata(void *handle);
const void *odoo_http_body(void *handle, size_t *length);
void odoo_http_cancel(void *handle);
void odoo_http_release(void *handle);
