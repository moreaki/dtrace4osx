#!/usr/sbin/dtrace -C -s

/* Syslogging DTrace Script  */

/* This is needed for the system() call */
#pragma D option destructive
#pragma D option quiet

fbt::*_fsync:entry {
    if (execname != "logger") {
        self->caller = execname;
        self->start  = timestamp;
    }
}
  
fbt::*_fsync:return {
    if (self->start) {
        this->end      = timestamp;
        this->duration = (this->end - self->start)/1000000;
        system("/bin/logger -p local1.info %s by %s in %d ms", probefunc, self->caller, this->duration);
        self->start = 0;
    }
}
