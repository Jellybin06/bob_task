#include <iostream>
#include <stdint.h>
#include <netinet/in.h>
#include <stdlib.h>

uint32_t sum_data(int argc, char*argv[]);
uint32_t read_file(int i, int argc, uint32_t* num, char *argv[]);

uint32_t sum_data(int argc, char *argv[]) {
    uint32_t num = 0;
    uint32_t sum = 0;
    for (int i = 1; i < argc; i++) {
        if(i>1) printf("+ ");
        if (read_file(i, argc, &num, argv) == -1) return -1;
        sum += num;
        printf("%d(0x%08x) ", num, num);
    }
    return sum;
}

uint32_t read_file(int i, int argc, uint32_t* num, char *argv[]) {
    uint32_t nl[argc];
    FILE* exFile = fopen(argv[i], "rb");
    fseek(exFile, 0, SEEK_END);
    int fileSize = ftell(exFile);
    if (exFile == NULL) {
        printf("File Not Exist");
        return -1;
    } else if (fileSize < 4) {
        printf("File Size is under 4Byte...\n");
        fclose(exFile);
        return -1;
    }
    rewind(exFile);
    if(fread(&nl[i], sizeof(nl[i]), 1, exFile) != 1) {
        printf("fread failed...");
        fclose(exFile);
        return -1;
    }
    *num = ntohl(nl[i]);
    fclose(exFile);
    return *num;
}

int main(int argc, char *argv[]) {
    uint32_t result = 0;
    if (argc < 3) {
        printf("argc need more than 1");
        return -1;
    }
    result = sum_data(argc, argv);
    if (result == -1) return -1;
    printf("= %d(0x%08x)\n", result, result);
    return 0;
}