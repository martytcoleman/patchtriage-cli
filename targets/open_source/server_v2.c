/*
 * mini_server v2.0 — patched version with security fixes.
 * Fixes: sprintf->snprintf, strcpy->strncpy, format string fix,
 *        content-length validation, bounds checking, stack canaries.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#define MAX_HEADERS 32
#define BUFFER_SIZE 256
#define MAX_PATH_LEN 255
#define MAX_HEADER_VALUE_LEN 127
#define MAX_BODY_SIZE 65536
#define MAX_CONTENT_LENGTH 1048576

typedef struct {
    char key[64];
    char value[128];
} Header;

typedef struct {
    char method[16];
    char path[256];
    char version[16];
    Header headers[MAX_HEADERS];
    int header_count;
    char *body;
    int body_length;
    int content_length;
} HttpRequest;

/* FIX: uses snprintf with explicit buffer size */
void format_log_entry(char *output, size_t output_size, const char *method,
                      const char *path, int status_code) {
    snprintf(output, output_size, "[%d] %s %s", status_code, method, path);
}

/* FIX: bounds-checked header value copy */
int parse_header_line(const char *line, Header *header) {
    char *colon = strchr(line, ':');
    if (!colon) return -1;

    int key_len = colon - line;
    if (key_len <= 0 || key_len >= (int)sizeof(header->key)) {
        return -1;  /* FIX: reject oversized keys */
    }
    strncpy(header->key, line, key_len);
    header->key[key_len] = '\0';

    /* skip ": " */
    const char *value = colon + 1;
    while (*value == ' ') value++;

    /* FIX: bounded copy with explicit length check */
    size_t value_len = strlen(value);
    if (value_len >= sizeof(header->value)) {
        value_len = sizeof(header->value) - 1;
    }
    strncpy(header->value, value, value_len);
    header->value[value_len] = '\0';
    return 0;
}

/* FIX: validates content_length is non-negative and within bounds */
int parse_content_length(const char *value) {
    char *endptr;
    errno = 0;
    long val = strtol(value, &endptr, 10);
    if (errno != 0 || endptr == value || *endptr != '\0') {
        fprintf(stderr, "Invalid Content-Length value: %s\n", value);
        return -1;
    }
    if (val < 0 || val > MAX_CONTENT_LENGTH) {
        fprintf(stderr, "Content-Length out of range: %ld\n", val);
        return -1;
    }
    return (int)val;
}

/* FIX: validates path length */
int validate_path(const char *path, size_t len) {
    if (len == 0 || len > MAX_PATH_LEN) {
        fprintf(stderr, "Invalid path length: %zu\n", len);
        return -1;
    }
    /* Check for path traversal */
    if (strstr(path, "..") != NULL) {
        fprintf(stderr, "Path traversal detected\n");
        return -1;
    }
    return 0;
}

/* parse "GET /path HTTP/1.1" */
int parse_request_line(const char *line, HttpRequest *req) {
    char *sp1 = strchr(line, ' ');
    if (!sp1) return -1;

    int method_len = sp1 - line;
    if (method_len > 15) method_len = 15;
    strncpy(req->method, line, method_len);
    req->method[method_len] = '\0';

    char *path_start = sp1 + 1;
    char *sp2 = strchr(path_start, ' ');
    if (!sp2) return -1;

    int path_len = sp2 - path_start;
    /* FIX: bounds check on path length */
    if (path_len >= (int)sizeof(req->path)) {
        fprintf(stderr, "Request path too long: %d bytes\n", path_len);
        return -1;
    }
    if (validate_path(path_start, path_len) != 0) {
        return -1;
    }
    strncpy(req->path, path_start, path_len);
    req->path[path_len] = '\0';

    /* FIX: bounded version copy */
    char *ver_start = sp2 + 1;
    strncpy(req->version, ver_start, sizeof(req->version) - 1);
    req->version[sizeof(req->version) - 1] = '\0';

    return 0;
}

/* FIX: no longer passes user data as format string */
void log_request(const char *client_info) {
    printf("%s\n", client_info);
}

/* URL decode: %XX -> char */
int url_decode(char *dst, size_t dst_size, const char *src) {
    size_t written = 0;
    while (*src && written < dst_size - 1) {
        if (*src == '%' && isxdigit(src[1]) && isxdigit(src[2])) {
            char hex[3] = {src[1], src[2], '\0'};
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
        written++;
    }
    *dst = '\0';
    if (*src != '\0') {
        fprintf(stderr, "URL decode: output buffer too small\n");
        return -1;
    }
    return 0;
}

HttpRequest *parse_http_request(const char *raw_request) {
    HttpRequest *req = malloc(sizeof(HttpRequest));
    if (!req) return NULL;
    memset(req, 0, sizeof(HttpRequest));

    /* copy so we can tokenize */
    size_t raw_len = strlen(raw_request);
    if (raw_len > MAX_BODY_SIZE * 2) {
        fprintf(stderr, "Request too large: %zu bytes\n", raw_len);
        free(req);
        return NULL;
    }

    char *buf = strdup(raw_request);
    if (!buf) { free(req); return NULL; }

    /* first line: request line */
    char *line = strtok(buf, "\r\n");
    if (!line || parse_request_line(line, req) != 0) {
        free(buf);
        free(req);
        return NULL;
    }

    /* headers */
    while ((line = strtok(NULL, "\r\n")) != NULL) {
        if (line[0] == '\0') break;  /* empty line = end of headers */

        if (req->header_count >= MAX_HEADERS) {
            fprintf(stderr, "Too many headers (max %d)\n", MAX_HEADERS);
            break;
        }

        if (parse_header_line(line, &req->headers[req->header_count]) == 0) {
            /* check for Content-Length */
            if (strcasecmp(req->headers[req->header_count].key,
                           "Content-Length") == 0) {
                int cl = parse_content_length(
                    req->headers[req->header_count].value);
                if (cl < 0) {
                    fprintf(stderr, "Rejecting request: bad Content-Length\n");
                    free(buf);
                    free(req);
                    return NULL;
                }
                req->content_length = cl;
            }
            req->header_count++;
        }
    }

    /* body (if any) */
    if (req->content_length > 0) {
        /* FIX: validate content_length against max body size */
        if (req->content_length > MAX_BODY_SIZE) {
            fprintf(stderr, "Body too large: %d bytes (max %d)\n",
                    req->content_length, MAX_BODY_SIZE);
            free(buf);
            free(req);
            return NULL;
        }

        char *body_start = strstr(raw_request, "\r\n\r\n");
        if (body_start) {
            body_start += 4;
            /* FIX: verify actual data length matches content_length */
            size_t available = strlen(body_start);
            if (available < (size_t)req->content_length) {
                fprintf(stderr, "Incomplete body: expected %d, got %zu\n",
                        req->content_length, available);
                free(buf);
                free(req);
                return NULL;
            }
            req->body = malloc(req->content_length + 1);
            if (req->body) {
                memcpy(req->body, body_start, req->content_length);
                req->body[req->content_length] = '\0';
                req->body_length = req->content_length;
            }
        }
    }

    free(buf);
    return req;
}

void free_request(HttpRequest *req) {
    if (req) {
        free(req->body);
        free(req);
    }
}

void print_request(const HttpRequest *req) {
    char log_buf[512];
    format_log_entry(log_buf, sizeof(log_buf), req->method, req->path, 200);
    printf("Log: %s\n", log_buf);
    printf("Method: %s\n", req->method);
    printf("Path: %s\n", req->path);
    printf("Version: %s\n", req->version);
    printf("Headers (%d):\n", req->header_count);
    for (int i = 0; i < req->header_count; i++) {
        printf("  %s: %s\n", req->headers[i].key, req->headers[i].value);
    }
    if (req->body) {
        printf("Body (%d bytes): %s\n", req->body_length, req->body);
    }
}

int main(int argc, char *argv[]) {
    const char *test_request =
        "GET /index.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: TestClient/1.0\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "Hello, World!";

    printf("=== mini_server v2.0 ===\n");
    printf("Parsing test request...\n");

    HttpRequest *req = parse_http_request(test_request);
    if (req) {
        print_request(req);
        log_request("Client connected from 127.0.0.1");
        free_request(req);
    } else {
        printf("Failed to parse request\n");
    }

    /* URL decode test */
    char decoded[256];
    if (url_decode(decoded, sizeof(decoded),
                   "/path%20with%20spaces?q=hello+world") == 0) {
        printf("Decoded URL: %s\n", decoded);
    }

    return 0;
}
