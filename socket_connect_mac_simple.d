#!/usr/sbin/dtrace -s

#pragma D option quiet
/* #pragma D option switchrate=10hz */
#pragma D option switchrate=1s
#pragma D option destructive 

inline int af_inet = 2;		/* AF_INET defined in bsd/sys/socket.h */

dtrace:::BEGIN
{
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

	printf("%-6s %-16s %-3s %-16s %-5s %8s %s\n", "PID", "PROCESS", "FAM",
	    "ADDRESS", "PORT", "LAT(us)", "RESULT");
}

/* MacOSX 10.10: 
	connect(int socket, const struct sockaddr *address, socklen_t address_len); 
	struct sockaddr {
		__uint8_t	sa_len;	
		sa_family_t	sa_family;	
		char		sa_data[14];	
	};
*/

syscall::connect:entry
{
    self->arg0 = arg0; /* int socket */
    self->arg1 = arg1; /* const struct sockaddr *address */
    self->arg2 = arg2; /* socklen_t address_len */
    self->in = 1;
}

syscall::connect:entry
/ self->in = 1 && execname == "nc" /
{
	printf("ENTERING /execname == nc/ [ENTRY] with %s\n", execname);
	/*
	trace(execname);
	ustack();
	*/
		
	this->len = *(socklen_t *) copyin((uintptr_t)self->arg2, sizeof(socklen_t));
    this->socks = (struct sockaddr *) copyin((uintptr_t)self->arg1, this->len);

	self->family = this->socks->sa_family;

    this->hport = (uint_t)(this->socks->sa_data[0]);
    this->lport = (uint_t)(this->socks->sa_data[1]);
    this->hport <<= 8;

    self->port = this->hport + this->lport;

    this->a1 = lltostr((uint_t)this->socks->sa_data[2]);
    this->a2 = lltostr((uint_t)this->socks->sa_data[3]);
    this->a3 = lltostr((uint_t)this->socks->sa_data[4]);
    this->a4 = lltostr((uint_t)this->socks->sa_data[5]);
    this->s1 = strjoin(this->a1, ".");
    this->s2 = strjoin(this->s1, this->a2);
    this->s1 = strjoin(this->s2, ".");
    this->s2 = strjoin(this->s1, this->a3);
    this->s1 = strjoin(this->s2, ".");

    self->address = strjoin(this->s1, this->a4);

	self->start = timestamp;
}

syscall::connect:return
/* /self->start/ */
/execname == "nc" /
{
	printf("ENTERING /execname == nc/ [RETURN] with %s\n", execname);
	this->delta = (timestamp - self->start) / 1000;
	this->errstr = err[errno] != NULL ? err[errno] : lltostr(errno);
	
	printf("%-6d %-16s %-3d %-16s %-5d %8d %s\n", pid, execname, self->family, self->address, self->port, this->delta, this->errstr);
	self->family = 0;
	self->address = 0;
	self->port = 0;
	self->start = 0;
	system("date");
	/* system("/usr/bin/printf \"%s by %s in %d ms\"", probefunc, self->caller, this->delta); */
}

syscall::connectx:entry {
	printf("ENTERING [syscall::connectx:entry -> 1] with %s\n", execname);
	this->s = (struct sockaddr_in *)copyin(arg3, sizeof (struct sockaddr)); 
	this->f = this->s->sin_family; 
	self->inconnectx = 1; 
} 

syscall::connectx:entry 
/ this->f == af_inet && execname == "nc" / 
{ 
	printf("ENTERING [syscall::connectx:entry -> 2] with %s\n", execname);
	self->family = this->f; 
	self->port = (this->s->sin_port & 0xFF00) >> 8; 
	self->port |= (this->s->sin_port & 0xFF) << 8; 
	this->a = (uint8_t *)&this->s->sin_addr; 
	this->addr1 = strjoin(lltostr(this->a[0] + 0ULL), strjoin(".", strjoin(lltostr(this->a[1] + 0ULL), "."))); 
	this->addr2 = strjoin(lltostr(this->a[2] + 0ULL), strjoin(".", strjoin(lltostr(this->a[1] + 0ULL), "."))); 
	this->addr2 = strjoin(lltostr(this->a[2] + 0ULL), strjoin(".", lltostr(this->a[3] + 0ULL))); 
	self->address = strjoin(this->addr1, this->addr2); 
	self->start = timestamp; 
}

syscall::connectx:return 
/ self->start && self->inconnectx = 1 / 
{ 
	printf("ENTERING [syscall::connectx:return -> 3] with %s\n", execname);
	system("date");
	
	this->delta = (timestamp - self->start) / 1000; 
	this->errstr = err[errno] != NULL ? err[errno] : lltostr(errno);
		
	printf("%-6d %-16s %-3d %-16s %-5d %8d %s\n", pid, execname, self->family, self->address, self->port, this->delta, this->errstr); 
	self->family = 0; 
	self->address = 0; 
	self->port = 0; 
	self->start = 0; 
}

