#!/bin/sh
# #!/usr/bin/sh
#
# dtruss - print process system call time details.
#          Written using DTrace (Solaris 10 3/05).
#
# 17-Jun-2005, ver 0.80         (check for newer versions)
#
# USAGE: dtruss [-acdeflhoLs] [-t syscall] { -p PID | -n name | command }
#
#          -p PID          # examine this PID
#          -n name         # examine this process name
#          -t syscall      # examine this syscall only
#          -a              # print all details
#          -c              # print system call counts
#          -d              # print relative timestamps (us)
#          -e              # print elapsed times (us)
#          -f              # follow children as they are forked
#          -l              # force printing of pid/lwpid per line
#          -o              # print on cpu times (us)
#          -s              # print stack backtraces
#          -L              # don't print pid/lwpid per line
#          -b bufsize      # dynamic variable buf size (default is "4m")
#  eg,
#       dtruss df -h       # run and examine the "df -h" command
#       dtruss -p 1871     # examine PID 1871
#       dtruss -n tar      # examine all processes called "tar"
#       dtruss -f test.sh  # run test.sh and follow children
#
# The elapsed times are interesting, to help identify syscalls that take
#  some time to complete (during which the process may have context
#  switched off the CPU).
#
# SEE ALSO: procsystime    # DTraceToolkit
#           dapptrace      # DTraceToolkit
#           truss
#
# COPYRIGHT: Copyright (c) 2005 Brendan Gregg.
#
# CDDL HEADER START
#
#  The contents of this file are subject to the terms of the
#  Common Development and Distribution License, Version 1.0 only
#  (the "License").  You may not use this file except in compliance
#  with the License.
#
#  You can obtain a copy of the license at Docs/cddl1.txt
#  or http://www.opensolaris.org/os/licensing.
#  See the License for the specific language governing permissions
#  and limitations under the License.
#
# CDDL HEADER END
#
# Author: Brendan Gregg  [Sydney, Australia]
#
# TODO: Track signals, more output formatting.
#
# 29-Apr-2005   Brendan Gregg   Created this.
# 09-May-2005      "      " 	Fixed evaltime (thanks Adam L.)
# 16-May-2005	   "      "	Added -t syscall tracing.
# 17-Jun-2005	   "      "	Added -s stack backtraces.
#


##############################
# --- Process Arguments ---
#

### Default variables
opt_pid=0; opt_name=0; pid=0; pname="."
opt_elapsed=0; opt_cpu=0; opt_counts=0;
opt_relative=0; opt_printid=0; opt_follow=0
opt_command=0; command=""; opt_buf=0; buf="30m"
opt_trace=0; trace="."; opt_stack=0;
opt_wait=0; wname="."; opt_has_target=0
opt_filter=0
### Process options
while getopts ab:cdefhln:op:st:LFW: name
do
        case $name in
	b)	opt_buf=1; buf=$OPTARG ;;
        p)      opt_pid=1; pid=$OPTARG ;;
        n)      opt_name=1; pname=$OPTARG ;;
        W)      opt_wait=1; wname=$OPTARG ;;
        t)      opt_trace=1; trace=$OPTARG ;;
	a)	opt_counts=1; opt_relative=1; opt_elapsed=1; opt_follow=1
		opt_printid=1; opt_cpu=1 ;;
	c)	opt_counts=1 ;;
	d)	opt_relative=1 ;;
	e)	opt_elapsed=1 ;;
	f)	opt_follow=1 ;;
	l)	opt_printid=1 ;;
	o)	opt_cpu=1 ;;
	L)	opt_printid=-1 ;;
	s)	opt_stack=-1 ;;
	F)	opt_filter=1 ;;
        h|?)    cat <<-END >&2
		USAGE: dtruss [-acdefholLFs] [-t syscall] { -p PID | -n name | command | -W name }

		          -p PID          # examine this PID
		          -n name         # examine this process name
		          -t syscall      # examine this syscall only
		          -W name         # wait for a process matching this name
		          -a              # print all details
		          -c              # print syscall counts
		          -d              # print relative times (us)
		          -e              # print elapsed times (us)
		          -f              # follow children
		          -l              # force printing pid/lwpid
		          -o              # print on cpu times
		          -s              # print stack backtraces
		          -L              # don't print pid/lwpid
		          -F              # filter out common & noisy syscalls
		          -b bufsize      # dynamic variable buf size
		   eg,
		       dtruss df -h       # run and examine "df -h"
		       dtruss -p 1871     # examine PID 1871
		       dtruss -n tar      # examine all processes called "tar"
		       dtruss -f test.sh  # run test.sh and follow children
		END
		exit 1
        esac
done
shift `expr $OPTIND - 1`

### Option logic
if [ $opt_pid -eq 0 -a $opt_name -eq 0 -a $opt_wait -eq 0 ]; then
	opt_pid=1
	opt_command=1
	if [ "$*" = "" ]; then
		$0 -h
		exit
	fi
	command="$*"	# yes, I meant $*!
fi
if [ $opt_wait -eq 1 ]; then
	opt_has_target=1
fi
if [ $opt_follow -eq 1 -o $opt_name -eq 1 ]; then
	if [ $opt_printid -ne -1 ]; then
		opt_printid=1
	else
		opt_printid=0
	fi
fi

### Option translation
## if [ "$trace" = "exec" ]; then trace="exece"; fi
if [ "$trace" = "exec" ]; then trace="execve"; fi


#################################
# --- Main Program, DTrace ---
#

### Define D Script
dtrace='
 #pragma D option quiet

 /*
  * Command line arguments
  */
 inline int OPT_has_target   = '$opt_has_target';
 inline int OPT_command   = '$opt_command';
 inline int OPT_follow    = '$opt_follow';
 inline int OPT_printid   = '$opt_printid';
 inline int OPT_relative  = '$opt_relative';
 inline int OPT_elapsed   = '$opt_elapsed';
 inline int OPT_cpu       = '$opt_cpu';
 inline int OPT_counts    = '$opt_counts';
 inline int OPT_pid       = '$opt_pid';
 inline int OPT_name      = '$opt_name';
 inline int OPT_trace     = '$opt_trace';
 inline int OPT_stack     = '$opt_stack';
 inline int OPT_filtercommon = '$opt_filter';
 inline int PID_OPT       = '$pid';
 inline string NAME       = "'"$pname"'";
 inline string TRACE      = "'$trace'";

 dtrace:::BEGIN
 {
	PID = PID_OPT;
	/* print header */
	/* OPT_printid  ? printf("%-8s  ","PID/LWP") : 1; */
	OPT_printid  ? printf("\t%-8s  ","PID/THRD") : 1;
	OPT_relative ? printf("%8s ","RELATIVE") : 1;
	OPT_elapsed  ? printf("%7s ","ELAPSD") : 1;
	OPT_cpu      ? printf("%6s ","CPU") : 1;
	printf("SYSCALL(args) \t\t = return\n");

	/* Apple: Names of top-level sysctl MIBs */
	sysctl_first[0] = "CTL_UNSPEC";
	sysctl_first[1] = "CTL_KERN";
	sysctl_first[2] = "CTL_VM";
	sysctl_first[3] = "CTL_VFS";
	sysctl_first[4] = "CTL_NET";
	sysctl_first[5] = "CTL_DEBUG";
	sysctl_first[6] = "CTL_HW";
	sysctl_first[7] = "CTL_MACHDEP";
	sysctl_first[9] = "CTL_MAXID";

	/* globals */
	/* variables for following child processes.
	 * trackedpid is indexed by PID; values:
	 * 0 = not tracing this process
	 * -1 = tracing this process
	 * >0 = thread ID (tid) during vfork call */
	trackedpid[pid] = 0;
	/* child: set to PID once a thread has been identified as part of a traced
	 * process due to its descendence from a traced process. Threads get recycled
	 * by other processes, so storing the PID here catches that case. */
	self->child = 0;

	self->follow_in_spawn_call = 0;
 }

 dtrace:::BEGIN
 /OPT_command && $1 > 0/
 {
	PID = $1;
	system("/bin/kill -CONT %d", $1);
 }


 /*
  * Save syscall entry info
  */


 /* Threads seem to be recycled on macOS, including thread-local DTrace
  * variables; check for mismatch between self->child and pid to detect and
  * reset the variables. */
 syscall:::entry
 /OPT_follow && (self->child != 0) && (self->child != pid)/
 {
	/* Clean up recycled threads */
	self->child = 0;
	self->start = (uint64_t)0;
	self->vstart = (uint64_t)0;
	self->arg0 = (uint64_t)0;
	self->arg1 = (uint64_t)0;
	self->arg2 = (uint64_t)0;
	self->arg3 = (uint64_t)0;
	self->arg4 = (uint64_t)0;
	self->arg5 = (uint64_t)0;
 }

 /* MacOS X: notice first appearance of child process´s thread from fork or
  * posix_spawn. Checking the own process for presence in the trackedpid table
  * also catches new threads in child processes whose parent process has died. */
 syscall:::entry
 /OPT_follow && 0 == self->child && (trackedpid[ppid] == -1 || trackedpid[pid] == -1)/
 {
	/* set as child */
	self->child = pid;
 }

 /* MacOS X: notice first appearance of child and parent from vfork */
 syscall:::entry
 /OPT_follow && trackedpid[ppid] > 0 && 0 == self->child/
 {
	/* set as child */
	this->vforking_tid = trackedpid[ppid];
	self->child = (this->vforking_tid == tid) ? 0 : pid;

	/* print output */
	self->code = errno == 0 ? "" : "Err#";
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",(this->vforking_tid == tid) ? ppid : pid,tid) : 1;
	OPT_relative ? printf("%8d:  ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d:  ",0) : 1;
	OPT_cpu      ? printf("%6d ",0) : 1;
	printf("%s()\t\t = %d %s%d\n","vfork",
	    (this->vforking_tid == tid) ? pid : 0,self->code,(int)errno);
 }

 /* Alternative detection of recycled threads: start time stamp is still set,
  * although no tracking criteria are met. Again, reset thread-local variables. */
 syscall:::entry
 /self->start &&
  !((OPT_has_target && pid == $target) ||
    (OPT_pid && pid == PID) ||
    (OPT_name && NAME == strstr(NAME, execname)) ||
    (OPT_name && execname == strstr(execname, NAME)) ||
    (self->child == pid))/
 {
	self->child = 0;
	self->start = (uint64_t)0;
	self->vstart = (uint64_t)0;
	self->arg0 = (uint64_t)0;
	self->arg1 = (uint64_t)0;
	self->arg2 = (uint64_t)0;
	self->arg3 = (uint64_t)0;
	self->arg4 = (uint64_t)0;
	self->arg5 = (uint64_t)0;
 }

 syscall:::entry
 /(OPT_has_target && pid == $target) ||
  (OPT_pid && pid == PID) ||
  (OPT_name && NAME == strstr(NAME, execname)) ||
  (OPT_name && execname == strstr(execname, NAME)) ||
  (self->child == pid)/
 {
	/* set start details */
	self->start = timestamp;
	self->vstart = vtimestamp;
	self->arg0 = arg0;
	self->arg1 = arg1;
	self->arg2 = arg2;

	/* count occurances */
	OPT_counts == 1 ? @Counts[probefunc] = count() : 1;
 }

/* 4, 5 and 6 arguments */
 syscall::select:entry,
 syscall::mmap:entry,
 syscall::pwrite:entry,
 syscall::pread:entry,
 syscall::openat:entry,
 syscall::unlinkat:entry,
 syscall::getattrlistat:entry,
 syscall::getattrlistbulk:entry,
 syscall::fstatat:entry,
 syscall::fstatat64:entry,
 syscall::readlinkat:entry,
 syscall::linkat:entry,
 syscall::fchownat:entry,
 syscall::renameat:entry,
 syscall::sysctl:entry,
 syscall::sysctlbyname:entry,
 syscall::faccessat:entry,
 syscall::kdebug_trace64:entry
 /(OPT_has_target && pid == $target) ||
  (OPT_pid && pid == PID) ||
  (OPT_name && NAME == strstr(NAME, execname)) ||
  (OPT_name && execname == strstr(execname, NAME)) ||
  (self->child == pid)/
 {
	self->arg3 = arg3;
	self->arg4 = arg4;
	self->arg5 = arg5;
 }

 syscall::posix_spawn:entry
 /(OPT_has_target && pid == $target) ||
  (OPT_pid && pid == PID) ||
  (OPT_name && NAME == strstr(NAME, execname)) ||
  (OPT_name && execname == strstr(execname, NAME)) ||
  (self->child == pid)/
 {
	/* Save the executable path as it often seems to be unavailable on return */
	self->arg1_str = (arg1 != 0 ? copyinstr(arg1) : "");
	self->arg3 = arg3;
	self->arg4 = arg4;
	self->arg5 = arg5;
 }

 syscall::execve:entry
 /(OPT_has_target && pid == $target) ||
  (OPT_pid && pid == PID) ||
  (OPT_name && NAME == strstr(NAME, execname)) ||
  (OPT_name && execname == strstr(execname, NAME)) ||
  (self->child == pid)/
 {
	// Save the PID as this is reported incorrectly in the :return probe
	self->execve_self_pid = pid;
	/* Copy the executable path from user space now, as the process will have an
	 * entirely new address space when execve() returns. */
	self->arg0_str = arg0 ? copyinstr(arg0) : "";
}


 /*
  * Follow children
  */
 syscall::fork:entry
 /OPT_follow && self->start/
 {
	/* track this parent process */
	trackedpid[pid] = -1;
 }

 syscall::vfork:entry
 /OPT_follow && self->start/
 {
	/* track this parent process */
	trackedpid[pid] = tid;
 }

 /* syscall::rexit:entry */
 syscall::exit:entry
 /(self->child != 0)/
 {
	/* forget child */
	self->child = 0;
	trackedpid[pid] = 0;
 }

 proc::proc_exit:exited
 /tracepid[args[0]->pr_pid] != 0/
 {
	/* Clears exited processes from the table in case the PID gets recycled */
	self->child = 0;
	tracepid[args[0]->pr_pid] = 0;
 }

 /* Follow posix_spawn()ed child processes */

 proc:mach_kernel:posix_spawn:create
 /OPT_follow &&
  ((OPT_has_target && pid == $target) ||
   (OPT_pid && pid == PID) ||
   (OPT_name && NAME == strstr(NAME, execname)) ||
   (OPT_name && execname == strstr(execname, NAME)) ||
   (self->child == pid))/
 {
	trackedpid[pid] = -1;
	self->follow_posix_spawn_child_pid = args[0]->pr_pid;
	self->follow_in_spawn_call = 1;
 }

 proc::posix_spawn:spawn-success
 /self->follow_in_spawn_call/
 {
	trackedpid[self->follow_posix_spawn_child_pid] = -1;

	self->follow_posix_spawn_child_pid = 0;
	self->follow_in_spawn_call = 0;
 }

 // If the posix_spawn() call failed, reset our state, ready for the next such call.
proc::posix_spawn:*-failure
/self->follow_in_spawn_call/
{
	self->follow_posix_spawn_child_pid = 0;
	self->follow_in_spawn_call = 0;
}


 /*
  * Check for syscall tracing
  */
 syscall:::entry
 /OPT_trace && probefunc != TRACE/
 {
	/* drop info */
	self->start = 0;
	self->vstart = 0;
	self->arg0 = (uint64_t)0;
	self->arg1 = (uint64_t)0;
	self->arg2 = (uint64_t)0;
	self->arg3 = (uint64_t)0;
	self->arg4 = (uint64_t)0;
	self->arg5 = (uint64_t)0;
 }

 /*
  * Print return data
  */

 /*
  * NOTE:
  *  The following code is written in an intentionally repetetive way.
  *  The first versions had no code redundancies, but performed badly during
  *  benchmarking. The priority here is speed, not cleverness. I know there
  *  are many obvious shortcuts to this code, Ive tried them. This style has
  *  shown in benchmarks to be the fastest (fewest probes, fewest actions).
  */

 /* print 3 args, return as hex */
 syscall::sigprocmask:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, 0x%X, 0x%X)\t\t = 0x%X %s%d\n",probefunc,
	    (int)self->arg0,self->arg1,self->arg2,(int)arg0,
	    self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }

 /* print 3 args, arg0 as a string */
 syscall::stat:return,
 syscall::stat64:return,
 syscall::lstat:return,
 syscall::lstat64:return,
 syscall::access:return,
 syscall::mkdir:return,
 syscall::chdir:return,
 syscall::chroot:return,
 syscall::getattrlist:return, /* XXX 5 arguments */
 syscall::chown:return,
 syscall::lchown:return,
 syscall::chflags:return,
 syscall::readlink:return,
 syscall::utimes:return,
 syscall::pathconf:return,
 syscall::truncate:return,
 syscall::getxattr:return,
 syscall::setxattr:return,
 syscall::removexattr:return,
 syscall::unlink:return,
 syscall::shm_open:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(\"%S\", 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,
	    self->arg0 ? copyinstr(self->arg0) : "[NULL]",self->arg1,self->arg2,(int)arg0,
	    self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }

 /* open() takes 2-3 args; arg0 as string, arg2 as octal file mode */
 syscall::open:return,
 syscall::open_nocancel:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data; default arg2 to 0 if O_CREAT not set */
	printf("%s(\"%S\", 0x%X, 0%o)\t\t = %d %s%d\n",probefunc,
		 self->arg0 ? copyinstr(self->arg0) : "[NULL]",self->arg1,(self->arg1 & 0x0200) ? self->arg2 : 0,(int)arg0,
		 self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }


 /* print 3 args, arg0 as a string, already copied (due to pid weirdness) */
 syscall::execve:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	/* For some reason execve:return always reports pid = 0, so print stored value */
	OPT_printid  ? printf("%5d/0x%x:  ", self->execve_self_pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(\"%S\", 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,
	    self->arg0_str,self->arg1,self->arg2,(int)arg0,
	    self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg0_str = 0;
	self->execve_self_pid = 0;
 }

 /* print 3 args, arg1 as a string, for read/write variant */
 syscall::write:return,
 syscall::write_nocancel:return,
 syscall::read:return,
 syscall::read_nocancel:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, \"%S\" (0x%X), 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
	    (arg0 == -1 || self->arg1 == 0) ? "" : stringof(copyin(self->arg1, arg0 < 1024 ? arg0 : 1024)), self->arg1, self->arg2,(int)arg0,
	    self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }

 /* print 3 args, arg1 as a string */
 syscall::mkdirat:return,
 syscall::unlinkat:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, \"%S\", 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
	    copyinstr(self->arg1),self->arg2,(int)arg0,
	    self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }

 /* print 3 args, arg0 and arg2 as strings */
 syscall::symlinkat:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(\"%S\", 0x%X, \"%S\")\t\t = %d %s%d\n",probefunc,
	    copyinstr(self->arg0), self->arg1, copyinstr(self->arg2), (int)arg0,
	    self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }


 /* print 2 args, arg0 and arg1 as strings */
 syscall::rename:return,
 syscall::symlink:return,
 syscall::link:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(\"%S\", \"%S\")\t\t = %d %s%d\n",probefunc,
	    copyinstr(self->arg0), copyinstr(self->arg1),
	    (int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }

 /* print 0 arg output */
 syscall::*fork:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s()\t\t = %d %s%d\n",probefunc,
	    (int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }

 /* Some processes seem to close a huge number of file descriptors they
  * never opened as a precautionary measure, which floods the trace, so
  * hide EBADF. */
 syscall::close:return,
 syscall::close_nocancel:return
 /self->start &&
  (OPT_filtercommon && arg0 == -1 && errno == 9)/
 {
	self->start = 0;
	self->vstart = 0;

	OPT_counts == 1 ? @CloseBadFDCounts[pid] = count() : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }

 /* print 1 decimal arg output */
 syscall::close:return,
 syscall::close_nocancel:return,
 syscall::fchdir:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(%d)\t\t = %d %s%d\n",probefunc,(int)self->arg0,
	    (int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }

 /* print 1 string arg output */
 syscall::chdir:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(\"%S\")\t\t = %d %s%d\n",probefunc,
		self->arg0 ? copyinstr(self->arg0) : "[NULL]",
		(int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }

 /* print 2 arg output */
 syscall::utimes:return,
 syscall::munmap:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
	    self->arg1,(int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }

 /* print pread/pwrite with 4 arguments */
 syscall::pread*:return,
 syscall::pwrite*:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, \"%S\", 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
	    stringof(copyin(self->arg1,self->arg2 < 1024 ? self->arg2 : 1024)),self->arg2,self->arg3,(int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
 }

 /* print 4 args, arg0 as string, arg1 as string, arg2 as decimal, arg3 as hex */
 syscall::listxattr:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(\"%S\", \"%S\", %u, 0x%X)\t\t = %d %s%d\n",probefunc,
	    copyinstr(self->arg0), self->arg1 ? copyinstr(self->arg1) : "[NULL]", self->arg2, self->arg3, (int)arg0,
	    self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
 }

 /* print 4 args, arg0 as string, arg3 as decimal: int lstat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) */
 syscall::lstat64_extended:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(\"%S\", 0x%X, 0x%X, %u)\t\t = %d %s%d\n",probefunc,
	    copyinstr(self->arg0), self->arg1,self->arg2,self->arg3,(int)arg0,
	    self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
 }


 /* print 4 args, arg0 as decimal FD, arg1 as string */
 syscall::openat:return,
 syscall::faccessat:return,
 syscall::fchmodat:return,
 syscall::readlinkat:return,
 syscall::fstatat:return,
 syscall::fstatat64:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(%d%s, \"%S\", 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,
	    (int32_t)self->arg0, self->arg0 == -2 ? " (AT_FDCWD)" : "", copyinstr(self->arg1),self->arg2,self->arg3,(int)arg0,
	    self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
 }

 /* print 4 args, arg1 and arg3 as strings */
 syscall::renameat:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, \"%S\", 0x%X, \"%S\")\t\t = %d %s%d\n",probefunc,
		self->arg0, copyinstr(self->arg1), self->arg2, copyinstr(self->arg3), (int)arg0,
	    self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
 }

 /* Apple: print the arguments passed to sysctl */
 syscall::sysctl:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	mib = copyin(self->arg0, self->arg1 * sizeof(int));
	mib1 = *(int *)mib;
	mib2 = *((int *)mib + 1);

	printf("%s(", probefunc);

	printf("[%s, ", (self->arg1 > 0) ? ((*(int *)mib > 0 && *(int *)mib < 9) ? sysctl_first[mib1] : "unknown") : 0);

	printf("%d, %d, %d, %d, %d] (%d), ",
	    (self->arg1 > 1) ? *((int *)mib + 1) : 0,
	    (self->arg1 > 2) ? *((int *)mib + 2) : 0,
	    (self->arg1 > 3) ? *((int *)mib + 3) : 0,
	    (self->arg1 > 4) ? *((int *)mib + 4) : 0,
	    (self->arg1 > 5) ? *((int *)mib + 5) : 0,
	    self->arg1);

	printf("0x%X, 0x%X, 0x%X, 0x%X)\t\t = %d %s%d\n",
	    self->arg2, self->arg3, self->arg4, self->arg5,
		(int)arg0, self->code, (int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
	self->arg4 = 0;
	self->arg5 = 0;
 }

 /* Apple: print the string provided to sysctlbyname */
 syscall::sysctlbyname:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(%s, 0x%X, 0x%X, 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,
	    copyinstr(self->arg0),
	    self->arg1,self->arg2,self->arg3,self->arg4,(int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
	self->arg4 = 0;
 }

 /* print 5 arguments */
 syscall::kdebug_trace64:return,
 syscall::select:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, 0x%X, 0x%X, 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
	    self->arg1,self->arg2,self->arg3,self->arg4,(int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
	self->arg4 = 0;
 }

 /* print 5 args, arg1 as string */
 syscall::fchownat:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, \"%S\", 0x%X, 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,
		self->arg0, copyinstr(self->arg1), self->arg2, self->arg3, self->arg4,
		(int)arg0,self->code,(int)errno);

	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
	self->arg4 = 0;
 }
 /* print 5 args, arg1 and arg3 as strings */
 syscall::linkat:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, \"%S\", 0x%X, \"%S\", 0x%X)\t\t = %d %s%d\n",probefunc,
		self->arg0, copyinstr(self->arg1), self->arg2, self->arg3 ? copyinstr(self->arg3) : "", self->arg4,
		(int)arg0,self->code,(int)errno);

	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
	self->arg4 = 0;
 }

 /* getattrlistbulk has 5 unusual arguments: */
 syscall::getattrlistbulk:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	this->attrs = (struct attrlist*)(self->arg1 ? copyin(self->arg1, sizeof(struct attrlist)) : NULL);
	/* print main data */
	printf("%s(%d, 0x%X { .bitmapcount = %d, .reserved = 0x%x, .commonattr = 0x%x, .volattr = 0x%x, .dirattr = 0x%x, .fileattr = 0x%x, .forkattr = 0x%x }, 0x%X, 0x%X, 0x%X)\t\t = %d %s%d\n", probefunc,
		(int32_t)self->arg0,
		// attrlist
		self->arg1,
		this->attrs ? this->attrs->bitmapcount : 0,
		this->attrs ? this->attrs->reserved : 0,
		this->attrs ? this->attrs->commonattr : 0,
		this->attrs ? this->attrs->volattr : 0,
		this->attrs ? this->attrs->dirattr : 0,
		this->attrs ? this->attrs->fileattr : 0,
		this->attrs ? this->attrs->forkattr : 0,
		self->arg2,self->arg3,self->arg4,(int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
	self->arg4 = 0;
 }


 /* getattrlistat has 6 arguments */
 syscall::getattrlistat:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, \"%S\", 0x%X, 0x%X, 0x%X, 0x%X)\t\t = 0x%X %s%d\n",probefunc,self->arg0,
		copyinstr(self->arg1),self->arg2,self->arg3,self->arg4,self->arg5, arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
	self->arg4 = 0;
	self->arg5 = 0;
 }

 /* fstat and fstat64 have 2 args: file descriptor and pointer */
 syscall::fstat:return,
 syscall::fstat64:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(%d, 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
	    self->arg1,(int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
 }

 /* kill has 2 args that should be shown as decimal*/
 syscall::kill:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(%d, %d)\t\t = %d %s%d\n",probefunc,self->arg0,
	    self->arg1,(int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
 }

 /* mmap has 6 arguments */
 syscall::mmap:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X)\t\t = 0x%X %s%d\n",probefunc,self->arg0,
	    self->arg1,self->arg2,self->arg3,self->arg4,self->arg5, arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
	self->arg4 = 0;
	self->arg5 = 0;
 }

 /* posix_spawn has 6 arguments, most of them too complicated to print here,
  * but PID and path are the most useful for tracing anyway. */
 syscall::posix_spawn:return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X -> PID %d, \"%S\" (0x%X), 0x%X, 0x%X, 0x%X, 0x%X)\t\t = 0x%X %s%d\n", probefunc,
		self->arg0, ((self->arg0 != 0) ? *(pid_t*)copyin(self->arg0, sizeof(pid_t)) : -1),
	  self->arg1_str, self->arg1,
	  self->arg2,
	  self->arg3,self->arg4,self->arg5, arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
	self->arg3 = 0;
	self->arg4 = 0;
	self->arg5 = 0;
	self->arg1_str = 0;
 }



 /* print 3 arg output - default */
 syscall:::return
 /self->start/
 {
	/* calculate elapsed time */
	this->elapsed = timestamp - self->start;
	self->start = 0;
	this->cpu = vtimestamp - self->vstart;
	self->vstart = 0;
	self->code = errno == 0 ? "" : "Err#";

	/* print optional fields */
	/* OPT_printid  ? printf("%5d/%d:  ",pid,tid) : 1; */
	OPT_printid  ? printf("%5d/0x%x:  ",pid,tid) : 1;
	OPT_relative ? printf("%8d ",vtimestamp/1000) : 1;
	OPT_elapsed  ? printf("%7d ",this->elapsed/1000) : 1;
	OPT_cpu      ? printf("%6d ",this->cpu/1000) : 1;

	/* print main data */
	printf("%s(0x%X, 0x%X, 0x%X)\t\t = %d %s%d\n",probefunc,self->arg0,
	    self->arg1,self->arg2,(int)arg0,self->code,(int)errno);
	OPT_stack ? ustack()    : 1;
	OPT_stack ? trace("\n") : 1;
	self->arg0 = 0;
	self->arg1 = 0;
	self->arg2 = 0;
 }

 /* print counts */
 dtrace:::END
 {
	OPT_counts == 1 ? printf("\n%-32s %16s\n","CALL","COUNT") : 1;
	OPT_counts == 1 ? printa("%-32s %@16d\n",@Counts) : 1;

	(OPT_counts == 1 && OPT_filtercommon == 1) ? printf("\n%-7s %16s\n","PID","EBADF CLOSE() COUNT") : 1;
	(OPT_counts == 1 && OPT_filtercommon == 1) ? printa("%7d %@16d\n", @CloseBadFDCounts) : 1;
 }
'

### Run DTrace
#if [ $opt_command -eq 1 ]; then
#	/usr/sbin/dtrace -x dynvarsize=$buf -x evaltime=postinit -n "$dtrace" \
#	    -c "$command" >&2
#else
#	/usr/sbin/dtrace -x dynvarsize=$buf -n "$dtrace" >&2
#fi

### Run DTrace (Mac OS X)
# Redirect the output to stderr so that it doesn't mingle with
# data going to the target's stdout
if [ $opt_wait -eq 1 ]; then
	/usr/sbin/dtrace -w -x defaultargs -x dynvarsize=$buf -n "$dtrace" \
	    -W "$wname" >&2
elif [ $opt_command -eq 1 ]; then
	# Getting dtrace to run the command means it'll run as root, so instead:
	#
	# Create a subshell and get it to send SIGSTOP to itself, suspending the process.
	# When it wakes back up, it will exec the command, so the command will
	# take over the subshell's process & PID
	(:; bash -c 'kill -STOP $PPID' ; exec $command ) &
	# Remember the subshell's PID
	command_pid=$!
	echo Process for running command "$command" with PID $command_pid started and suspended. Launching dtrace, which will resume it:
	# Launch dtruss via sudo and pass the subshell's PID in. We've already enabled
	# OPT_command, so on startup, dtrace will resume the PID we passed in.
	# Note that we need -w as resuming processes is considered "destructive".
	/usr/bin/sudo /usr/sbin/dtrace -w -x dynvarsize=$buf -x evaltime=preinit -Z -n "$dtrace" \
	    "$command_pid" >&2 || kill $command_pid

else
	/usr/sbin/dtrace -x defaultargs -w -x dynvarsize=$buf -n "$dtrace" >&2
fi
