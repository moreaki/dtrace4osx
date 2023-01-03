# dtrace4osx
Various dtrace scripts.

Disable SIP to make the scripts work.

## Usage

### Generally:

Invoke the scripts as follows:

```
% sudo ./src/<scriptname.d>
```

### Specific 

- `src/syscall.d`

```
% sudo ./syscall.d -c date
```

## Caveats

- The scripts don't work with newer kernels.
- The scripts don't work on M1 or M2 arch (for now)

## Further resources

Look at `/usr/bin/dtruss` for a good overview on how to use dtrace.

- https://www.brendangregg.com/blog/2008-02-18/dtracetoolkit-in-macosx.html
- https://tsuiyuenhong.medium.com/using-dtrace-in-macos-and-ios-simulator-3c3a1ad583f1
- https://illumos.org/books/dtrace/bookinfo.html#bookinfo
- http://www.bignerdranch.com/blog/hooked-on-dtrace-part-1/
- http://rhizomeis.wordpress.com/2012/11/14/tracing-udp-backdoor-activity-on-macos-x/
- http://dtrace.org/guide/chapter12.html#chp-fmt-print
- http://www.joyent.com/blog/dtrace-caller-builtin
- https://docs.oracle.com/cd/E19253-01/819-5488/gbxwv/index.html
- https://wiki.freebsd.org/DTrace/One-Liners
- https://en.wikipedia.org/wiki/DTrace
- https://bignerdranch.com/blog/hooked-on-dtrace-part-1/
- https://github.com/opendtrace
- https://github.com/opensource-apple/dtrace
- https://www.oracle.com/solaris/technologies/dtrace-tutorial.html
- https://gitlab.com/pmdj/macos-dtrace-scripts
- https://poweruser.blog/using-dtrace-with-sip-enabled-3826a352e64b
- https://github.com/lunixbochs/ghostrace
- https://github.com/TritonDataCenter/dtruss-osx
- https://github.com/lundman/dtruss
- https://github.com/brummett/dtruss
- https://apple.stackexchange.com/questions/208762/now-that-el-capitan-is-rootless-is-there-any-way-to-get-dtrace-working
- https://stackoverflow.com/questions/60908765/mac-osx-using-dtruss

