#!/usr/sbin/dtrace -s
/* Flowindent DTrace Script  */

#pragma D option quiet
#pragma D option destructive
#pragma D option flowindent

BEGIN {
    printf("waiting for 'ls'");
}

syscall::open:entry
/execname == "ls" && guard++ == 0/ {
    self->traceIt = 1;
}

fbt:::
/self->traceIt/ {
}

syscall:::return
/self->traceIt/ {
    self->traceIt = 0;
	exit(0);
}
