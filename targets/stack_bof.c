#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);
}

int main(void) {
    char input[1024];
    int n = fread(input, 1, sizeof(input) - 1, stdin);
    input[n] = '\0';
    vulnerable(input);
    return 0;
}
