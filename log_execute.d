/* Syslogging DTrace Script  */

#pragma D option quiet
#pragma D option destructive /* This allows for system() calls */

fbt::*_fsync:entry
/ execname != "logger" /
{
        self->caller = execname;
        self->start  = timestamp;
}
  
fbt::*_fsync:return
/self->start/
{
        this->end      = timestamp;
        this->duration = (this->end - self->start)/1000000;

        system("/bin/logger -p local1.info %s by %s in %d ms", probefunc, self->caller, this->duration);

        self->start = 0;
}
