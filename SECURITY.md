# Security policy

## Reporting a vulnerability

Report a vulnerability in private, through GitHub: on the
[Security tab](https://github.com/linouxis9/oxirush-gtp-u/security) of this
repository, choose **Report a vulnerability**. Do not open a public issue
for it.

Say in the report:

- the version or the commit of the crate, its features, the Rust version,
  the target and, for the `tun` and `ebpf` features, the Linux version;
- the octets or the calls that show the problem, as a test or a short
  program when you can;
- what happens and what you expected: a panic, a read or a write out of
  bounds, a packet that reaches a tunnel it does not belong to, a TUN, a
  route or an eBPF program that stays behind;
- the clause of the specification, when the report rests on one.

The answer comes in the report itself. A fix is released as a new version
of the crate, with an advisory that credits you unless you ask otherwise.

There is no bug bounty.

## Supported versions

Fixes go into the latest release. An older version gets none.

## What to know before reporting

GTP-U has no authentication: whoever reaches the socket of an endpoint can
send on its tunnels, as the README says. That is the protocol and not a
vulnerability of this crate. The crate has not had a security audit. The
`tun` and `ebpf` features run with `CAP_NET_ADMIN` and `CAP_BPF`, and the
eBPF programs are loaded from an object that is committed with its source:
a report on any of these is welcome.
