#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define NOB_IMPLEMENTATION
#include "nob.h"

int main(int argc, char **argv) {
    NOB_GO_REBUILD_URSELF(argc, argv);

    const char *program = *argv++;
    if (program == NULL) {
        printf("Usage: nob [--release]\n");
        return 1;
    }
    const char *flag = *argv++;

    bool release;
    if (flag == NULL) {
        release = false;
    } else if (strncmp(flag, "--release", 9) == 0) {
        release = true;
    } else {
        printf("Unknown flag '%s'.\nUsage: nob [--release]\n", flag);
        return 1;
    }

    Nob_Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    nob_cmd_append(&cmd, "-std=c11", "-pedantic", "-Wpedantic",
                   "-Iisocline/include", "-Wno-unused-function");
    if (release) {
        nob_cmd_append(&cmd, "-O3");
    } else {
        nob_cmd_append(&cmd, "-g", "-ggdb2");
    }
    nob_cc_inputs(&cmd, "sz.c", "main.c", "isocline/src/isocline.c");
    nob_cc_output(&cmd, "schwatz");
    nob_cmd_append(&cmd, "-lpthread", "-lsodium");

    if (!nob_cmd_run(&cmd))
        return 1;
}
