/*
 * mini_server v1.0 — deliberately vulnerable mini HTTP request parser.
 * Contains: buffer overflow (sprintf), missing bounds checks, strcpy usage,
 *           format string issue, no stack protection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_HEADERS 32
#define BUFFER_SIZE 256

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

/* VULN: uses sprintf — no bounds checking on output buffer */
void format_log_entry(char *output, const char *method, const char *path,
                      int status_code) {
    sprintf(output, "[%d] %s %s", status_code, method, path);
}

/* VULN: uses strcpy — no bounds checking */
int parse_header_line(const char *line, Header *header) {
    char *colon = strchr(line, ':');
    if (!colon) return -1;

    int key_len = colon - line;
    strncpy(header->key, line, key_len);
    header->key[key_len] = '\0';

    /* skip ": " */
    const char *value = colon + 1;
    while (*value == ' ') value++;

    /* VULN: unbounded copy into fixed buffer */
    strcpy(header->value, value);
    return 0;
}

/* VULN: no validation on content_length; negative values accepted */
int parse_content_length(const char *value) {
    return atoi(value);
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
    /* VULN: no check if path_len > sizeof(req->path) */
    strncpy(req->path, path_start, path_len);
    req->path[path_len] = '\0';

    char *ver_start = sp2 + 1;
    strcpy(req->version, ver_start);  /* VULN: unbounded */

    return 0;
}

/* VULN: format string — user data passed directly to printf format */
void log_request(const char *client_info) {
    printf(client_info);
    printf("\n");
}

/* URL decode: %XX -> char */
void url_decode(char *dst, const char *src) {
    while (*src) {
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
    }
    *dst = '\0';
}

HttpRequest *parse_http_request(const char *raw_request) {
    HttpRequest *req = malloc(sizeof(HttpRequest));
    if (!req) return NULL;
    memset(req, 0, sizeof(HttpRequest));

    /* copy so we can tokenize */
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

        if (req->header_count >= MAX_HEADERS) break;  /* at least this is checked */

        if (parse_header_line(line, &req->headers[req->header_count]) == 0) {
            /* check for Content-Length */
            if (strcasecmp(req->headers[req->header_count].key,
                           "Content-Length") == 0) {
                req->content_length = parse_content_length(
                    req->headers[req->header_count].value);
            }
            req->header_count++;
        }
    }

    /* body (if any) */
    if (req->content_length > 0) {
        char *body_start = strstr(raw_request, "\r\n\r\n");
        if (body_start) {
            body_start += 4;
            req->body = malloc(req->content_length + 1);
            if (req->body) {
                /* VULN: trusts content_length without verifying actual data length */
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
    format_log_entry(log_buf, req->method, req->path, 200);
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

    printf("=== mini_server v1.0 ===\n");
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
    url_decode(decoded, "/path%20with%20spaces?q=hello+world");
    printf("Decoded URL: %s\n", decoded);

    return 0;
}
