#!/usr/sbin/dtrace -s

//TODO: does not work on M1 or M2 kernels

#pragma D option quiet
#pragma D option destructive
#pragma D option flowindent
#pragma D option switchrate=10hz 

BEGIN {
    printf("Tracing TCP functions");
}

fbt:mach_kernel:tcp_*:entry {
	printf("%d %Y %s [%d]\n", curpsinfo->pr_pid, walltimestamp, curpsinfo->pr_fname, curpsinfo->pr_argc);
}
