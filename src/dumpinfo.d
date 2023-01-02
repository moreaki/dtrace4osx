#!/usr/sbin/dtrace -s

#pragma D option quiet

pid$target::*viewDidLoad*:entry {
    printf("pid = %d\n", pid);
    printf("tid = %d\n", tid);
    printf("timestamp = %d\n", timestamp);
    printf("walltimestamp %d\n", walltimestamp);
    printf("probefunc = %s \n", probefunc);
    printf("probemod = %s\n", probemod);
    printf("probename = %s \n", probename);
    printf("probeprov = %s\n", probeprov);
}
