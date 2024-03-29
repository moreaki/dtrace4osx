#!/usr/sbin/dtrace -s

#pragma D option quiet

BEGIN {
	start = timestamp;
}

syscall:::entry {
    if (pid == $target) {
	    @[probefunc] = count();
	}
}

END {
	printf("total time: %d ms", (timestamp - start) / 1000000);
}
