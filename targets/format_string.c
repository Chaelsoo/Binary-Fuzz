#include <stdio.h>

int main(void) {
    char buf[512];
    int n = fread(buf, 1, sizeof(buf) - 1, stdin);
    buf[n] = '\0';
    printf(buf);  // format string vulnerability
    return 0;
}
