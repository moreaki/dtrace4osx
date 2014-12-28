#!/usr/sbin/dtrace -s

#pragma D option quiet
/* #pragma D option switchrate=10hz */
#pragma D option switchrate=1s
#pragma D option destructive 

inline int af_inet = 2;		/* AF_INET defined in /usr/include/sys/socket.h */

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
	err[EADDRNOTAVAIL] = "Can't assign requested address";

	printf("%-6s %-16s %-6s %-16s %-5s %8s %s\n", "PID", "PROCNAME", "FAMILY", "ADDRESS", "PORT", "LAT(us)", "RESULT");
}

/*  MacOSX connectx() syscall:

	connectx(arg0:int s, arg1:struct sockaddr *src, arg2:socklen_t srclen, 
						 arg3:struct sockaddr *dsts, arg4:socklen_t dstlen, 
		 				 arg5:uint32_t ifscope, arg6: associd_t aid, arg7:connid_t *cid);

	struct sockaddr_in {
		__uint8_t	sin_len;
		sa_family_t	sin_family;
		in_port_t	sin_port;
		struct	in_addr sin_addr;
		char		sin_zero[8];
	};

	struct sockaddr {
		__uint8_t	sa_len;	
		sa_family_t	sa_family;
		char		sa_data[14];
	};
*/

syscall::connectx:entry {
	/* DEBUG: printf("ENTERING [syscall::connectx:entry -> 1] with %s\n", execname); */
	this->s = (struct sockaddr_in *)copyin(arg3, sizeof (struct sockaddr)); 
	this->f = this->s->sin_family;
	self->arg0 = arg0;
	self->arg1 = arg1; /* Source Socket */
	self->arg2 = arg2; /* Source size */
	self->arg3 = arg3; /* Destination Socket */
	self->arg4 = arg4; /* Destination size */
	self->inconnectx = 1; 
} 

syscall::connectx:entry 
/ this->f == af_inet && execname == "nc" / 
{ 
	/* DEBUG: printf("ENTERING [syscall::connectx:entry -> 2] with %s\n", execname); */
	self->family = this->f;
	self->port = (this->s->sin_port & 0xFF00) >> 8; 
	self->port |= (this->s->sin_port & 0xFF) << 8;
	
	/*
	this->len = *(socklen_t *) copyin((uintptr_t)self->arg4, sizeof(socklen_t));
	this->socks = (struct sockaddr *) copyin((uintptr_t)self->arg3, this->len);
	this->hport = (uint_t)(this->socks->sa_data[0]);
	this->lport = (uint_t)(this->socks->sa_data[1]);
	this->hport <<= 8;
	self->port = this->hport + this->lport;
	*/
	
	this->a = (uint8_t *)&this->s->sin_addr; 
	this->addr1 = strjoin(lltostr(this->a[0] + 0ULL), strjoin(".", strjoin(lltostr(this->a[1] + 0ULL), "."))); 
	this->addr2 = strjoin(lltostr(this->a[2] + 0ULL), strjoin(".", strjoin(lltostr(this->a[1] + 0ULL), "."))); 
	this->addr2 = strjoin(lltostr(this->a[2] + 0ULL), strjoin(".", lltostr(this->a[3] + 0ULL))); 
	self->address = strjoin(this->addr1, this->addr2); 
	self->start = timestamp; 
}

syscall::connectx:return 
/ self->start / 
{ 
	/* DEBUG: printf("ENTERING [syscall::connectx:return -> 3] with %s\n", execname); */
	this->delta = (timestamp - self->start) / 1000; 
	this->errstr = err[errno] != NULL ? err[errno] : lltostr(errno);

	/* Basically anything can be called here */
	system("date");
		
	printf("%-6d %-16s %-6d %-16s %-5d %8d %s\n", pid, execname, self->family, self->address, self->port, this->delta, this->errstr); 
	self->family = 0; 
	self->address = 0; 
	self->port = 0; 
	self->start = 0; 
}
