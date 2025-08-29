#define NOB_IMPLEMENTATION
#include "nob.h"

int main(int argc, char **argv) {
    NOB_GO_REBUILD_URSELF(argc, argv);

    Nob_Procs procs = {};
    Nob_Cmd cmd = {};
    nob_cc(&cmd);
    nob_cc_flags(&cmd);
    nob_cmd_append(&cmd, "-std=c99", "-g", "-ggdb2", "-pedantic", "-Wpedantic");
    nob_cc_inputs(&cmd, "main.c");
    nob_cc_output(&cmd, "schwatz");
    nob_cmd_append(&cmd, "-lpthread", "-lsodium");

    if (!nob_cmd_run(&cmd))
        return 1;
}
