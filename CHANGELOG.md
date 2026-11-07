# Changelog

## Unreleased

- The keywords take `gtp` in the place of `3gpp`, and the description says 5GS and EPS (5G and 4G LTE), as those who look for the crate search.

## 0.1.0 - 2026-10-24

First release.

- A GTPv1-U codec (TS 29.281): every header field, the chain of extension
  headers with a variant for each type of V19.2.0 §5.2.2, the information
  elements, the PDU Session Container of TS 38.415 V19.1.0 §5.5.2 and the
  PDU Set Information Container of §6.5.2. Decoding never panics, and what
  it decodes encodes to a message that decodes to the same value. A
  message with one extension header at most, as a G-PDU on N3, is decoded
  and encoded without an allocation, and an endpoint sends it without one.
  An `Error` names the `Part` of the message and has the numbers that
  disagree.
- `MessageType`, `ExtensionHeaderType`, `InformationElementType` and
  `Cause`, with the names of the specification.
- `Endpoint`: the N3 socket of a gNB, or the S1-U socket of an eNB, and its
  tunnels, with the replies that TS 29.281 §7 asks of it, within limits
  for what a peer without a tunnel can make it send and log. It sends Echo
  Requests with T3-RESPONSE and N3-REQUESTS, supervises paths as TS 23.007
  §20.3.1 has it, and delivers its peers' path messages (`echo`,
  `supervise`, `path_events`).
- `upf_sim::UpfSimulator` and the `oxirush-upf-sim` program: a UPF to test
  against, without PFCP, with an echo service that a program which
  answers the UE itself turns off.
- `tun` (Linux): TUN devices and their routing, over rtnetlink, for the
  tunnels of an endpoint and the sessions of the test UPF.
- `ebpf` (Linux 6.6, little-endian): TCX programs that carry an
  endpoint's tunnels in the kernel. Their object is committed with its
  source; CI rebuilds it.
- Features `endpoint` (the default), `tun`, `ebpf`, `serde`, and `cli` for
  the program. Without the default features the crate has no dependency.
  Rust 1.88 or later.
