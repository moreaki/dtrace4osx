#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option destructive 

/* AF_INET{6} are unknown to dtrace, so replace them with numbers */
inline int af_inet  =  2; /* AF_INET  */
inline int af_inet6 = 30; /* AF_INET6 */
inline const string procname = "nc";
	
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

	printf("%-6s %-20s %-8s %-21s %-21s %-8s %s\n", 
		"PID", "PROCNAME", "FAMILY", "S_ADDR:S_PORT", "D_ADDR:D_PORT",
		"LAT(us)", "RESULT");
}

/*  MacOSX connectx() syscall:

	connectx(arg0:int s, arg1:struct sockaddr *src, arg2:socklen_t srclen, 
						 arg3:struct sockaddr *dsts, arg4:socklen_t dstlen, 
		 				 arg5:uint32_t ifscope, arg6: associd_t aid,
						 arg7:connid_t *cid);
*/

syscall::connectx:entry
{
	this->s = (struct sockaddr_in *) copyin(arg3, sizeof(struct sockaddr)); 
	this->f = this->s->sin_family;
} 

syscall::connectx:entry 
/ this->f == af_inet && execname == procname / 
{ 
	this->s = (struct sockaddr_in *) copyin(arg1, sizeof(struct sockaddr)); 
	self->address = inet_ntop(this->f, (void *) &this->s->sin_addr);
	self->port = ntohs(this->s->sin_port);
	self->s_addr = strjoin(strjoin(self->address, ":"), lltostr(self->port));
	
	this->d = (struct sockaddr_in *) copyin(arg3, sizeof(struct sockaddr)); 
	self->address = inet_ntop(this->f, (void *) &this->d->sin_addr);
	self->port = ntohs(this->d->sin_port);	
	self->d_addr = strjoin(strjoin(self->address, ":"), lltostr(self->port));
	
	self->ts = timestamp; 
}

syscall::connectx:entry
/ this->f == af_inet6 && execname == procname /
{
	this->s6 = (struct sockaddr_in6 *) copyin(arg1, sizeof(struct sockaddr_in6));
	self->port = ntohs(this->s6->sin6_port);
	self->address = inet_ntop(this->f, (void *) &this->s6->sin6_addr);
	self->s_addr = strjoin(strjoin(self->address, ":"), lltostr(self->port));
	
	this->d6 = (struct sockaddr_in6 *) copyin(arg3, sizeof(struct sockaddr_in6));
	self->port = ntohs(this->d6->sin6_port);
	self->address = inet_ntop(this->f, (void *) &this->d6->sin6_addr);
	self->d_addr = strjoin(strjoin(self->address, ":"), lltostr(self->port));
	
	self->ts = timestamp;
}

syscall::connectx:return 
/ self->ts / 
{ 
	this->delta = (timestamp - self->ts) / 1000; 
	this->errstr = err[errno] != NULL ? err[errno] : lltostr(errno);

	/* Basically anything can be called here */
	/* system("date"); */
	printf("%-6d %-20s %-8d %-21s %-21s %-8d %s\n", 
		pid, execname, this->f, self->s_addr, self->d_addr,
		this->delta, this->errstr);
	
	self->family = 0; 
	self->ts = 0; 
}
