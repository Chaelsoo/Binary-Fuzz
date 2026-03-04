#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *ptr = NULL;
    char buf[256];
    int n = fread(buf, 1, sizeof(buf) - 1, stdin);
    buf[n] = '\0';

    for (int i = 0; i < n; i++) {
        switch (buf[i]) {
            case 'A':
                ptr = malloc(64);
                if (ptr) strcpy(ptr, "allocated");
                break;
            case 'F':
                free(ptr);  // bug: no ptr = NULL
                break;
            case 'R':
                free(ptr);  // double-free → SIGABRT
                break;
        }
    }
    return 0;
}
