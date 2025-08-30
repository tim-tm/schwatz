#define NOB_IMPLEMENTATION
#include "nob.h"

int main(int argc, char **argv) {
    NOB_GO_REBUILD_URSELF(argc, argv);

    Nob_Cmd cmd = {0};
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    nob_cmd_append(&cmd, "-std=c11", "-g", "-ggdb2", "-pedantic", "-Wpedantic",
                   "-Iisocline/include", "-Wno-unused-function");
    nob_cc_inputs(&cmd, "sz.c", "main.c", "isocline/src/isocline.c");
    nob_cc_output(&cmd, "schwatz");
    nob_cmd_append(&cmd, "-lpthread", "-lsodium");

    if (!nob_cmd_run(&cmd))
        return 1;
}
