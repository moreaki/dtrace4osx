#!/usr/sbin/dtrace -C -s

/* Syslogging DTrace Script  */

#pragma D option quiet
#pragma D option destructive

fbt::*_fsync:entry
/ execname != "logger" / {
        self->caller = execname;
        self->start  = timestamp;
}
  
fbt::*_fsync:return
/self->start/ {
        this->end      = timestamp;
        this->duration = (this->end - self->start)/1000000;
        system("/bin/logger -p local1.info %s by %s in %d ms", probefunc, self->caller, this->duration);
        self->start = 0;
}
