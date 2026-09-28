# Changelog

## 0.1.0 (unreleased)

First release.

- GTPv1-U codec (TS 29.281): every header field, extension header chains,
  information elements, and constructors for Echo Request and Response, Error
  Indication, Supported Extension Headers Notification, End Marker and
  G-PDUs. Decoding follows the receiver rules of §5.1 and never panics;
  what it produces encodes to a message that decodes to the same value.
- PDU Session Container (TS 38.415 V18 §5.5.2): downlink and uplink PDU
  Session Information with their QoS monitoring, sequence number, delay and
  congestion fields; new IEs of later releases are kept as received. The
  wire format is checked against Wireshark's dissector and was exchanged
  with the free5GC and Open5GS UPFs.
- `Endpoint`: a gNB's N3 socket and tunnels. It answers Echo Requests,
  sends Error Indication and Supported Extension Headers Notification to
  port 2152, and delivers G-PDUs, End Markers and the peer's Error
  Indications with their source address; the TEID alone identifies a
  tunnel.
- `upf_sim::UpfSimulator` and the `oxirush-upf-sim` binary: a test UPF with
  an IPv4 UDP and ICMP echo service, End Marker on a path switch, and an
  optional TUN per session.
- `tun::TunPort` (Linux, `tun` feature): TUN devices with policy, VRF or UPF
  routing set up over rtnetlink, and without IPv6 addresses, so Linux sends
  nothing through them unasked.
- IPv4 UDP and ICMP Echo helpers to exercise tunnels without a TUN.
- Features: `endpoint` (default), `tun`, `serde`. Without default features
  the crate has no dependencies. MSRV 1.85.
