#!/usr/sbin/dtrace -s

//TODO: Needs to be updated to newest kernel structures in macOS Monterey and higher

#pragma D option quiet
#pragma D option switchrate=10hz
// This allows for system() calls
#pragma D option destructive

dtrace:::BEGIN {
	/* Add translations as desired from /usr/include/sys/errno.h */
	err[0]            = "Success";
	err[EINTR]        = "Interrupted syscall";
	err[EIO]          = "I/O error";
	err[EACCES]       = "Permission denied";
	err[ENETDOWN]     = "Network is down";
	err[ENETUNREACH]  = "Network unreachable";
	err[ECONNRESET]   = "Connection reset";
	err[ECONNREFUSED] = "Connection refused";
	err[ETIMEDOUT]    = "Timed out";
	err[EHOSTDOWN]    = "Host down";
	err[EHOSTUNREACH] = "No route to host";
	err[EINPROGRESS]  = "In progress";

	printf("%-6s %-16s %-3s %-16s %-5s %8s %s\n", "PID", "PROCESS", "FAM", "ADDRESS", "PORT", "LAT(us)", "RESULT");
}


fbt::tcp_input:entry {
        self->tcp = 1;
        self->start  = timestamp;
}

fbt::tcp_input:return
/self->start/ {
        this->end      = timestamp;
        this->duration = (this->end - self->start)/1000000;

        /* system("/bin/logger -p local1.info %s by %s in %d ms", probefunc, self->caller, this->duration); */
        self->start = 0;
}

syscall::connect*:entry {
	/* assume this is sockaddr_in until we can examine family */
	this->s = (struct sockaddr_in *)copyin(arg1, sizeof (struct sockaddr));
	this->f = this->s->sin_family;
}

syscall::connect*:entry
/this->f == af_inet/ {
	self->family = this->f;

	/* Convert port to host byte order without ntohs() being available. */
	self->port = (this->s->sin_port & 0xFF00) >> 8;
	self->port |= (this->s->sin_port & 0xFF) << 8;

	/*
	 * Convert an IPv4 address into a dotted quad decimal string.
	 * Until the inet_ntoa() functions are available from DTrace, this is
	 * converted using the existing strjoin() and lltostr().  It's done in
	 * two parts to avoid exhausting DTrace registers in one line of code.
	 */
	this->a = (uint8_t *)&this->s->sin_addr;
	this->addr1 = strjoin(lltostr(this->a[0] + 0ULL), strjoin(".", strjoin(lltostr(this->a[1] + 0ULL), ".")));
	this->addr2 = strjoin(lltostr(this->a[2] + 0ULL), strjoin(".", lltostr(this->a[3] + 0ULL)));
	self->address = strjoin(this->addr1, this->addr2);
	self->start = timestamp;
}

syscall::connect*:return
/self->start/ {
	this->delta = (timestamp - self->start) / 1000;
	this->errstr = err[errno] != NULL ? err[errno] : lltostr(errno);
	printf("%-6d %-16s %-3d %-16s %-5d %8d %s\n", pid, execname, self->family, self->address, self->port, this->delta, this->errstr);
	self->family = 0;
	self->address = 0;
	self->port = 0;
	self->start = 0;
}
