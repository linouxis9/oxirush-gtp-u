// The side of go-gtp in the comparison that ../compare.sh runs: the cases of
// ../src/bin/compare.rs, on the same G-PDUs, with the same output.
//
//	go run . decode-container 10000000
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/wmnsk/go-gtp/gtpv1"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

const teid = 0x12345678

var sink int

// The time, the allocations and their octets from its start.
type meter struct {
	start  time.Time
	before runtime.MemStats
}

type measured struct {
	elapsed             time.Duration
	allocations, octets uint64
}

func start() *meter {
	m := &meter{}
	runtime.GC()
	runtime.ReadMemStats(&m.before)
	m.start = time.Now()
	return m
}

func (m *meter) stop() measured {
	elapsed := time.Since(m.start)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	return measured{elapsed, after.Mallocs - m.before.Mallocs, after.TotalAlloc - m.before.TotalAlloc}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: gogtp <case> <iterations>")
		os.Exit(2)
	}
	name := os.Args[1]
	iterations, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = 0x45
	}
	// Flags 0x30: version 1, GTP, no optional field; 0x34 with the E flag.
	plain := message.NewHeader(0x30, message.MsgTypeTPDU, teid, 0, payload)
	container := message.NewHeaderWithExtensionHeaders(0x34, message.MsgTypeTPDU, teid, 0, payload,
		message.NewExtensionHeader(message.ExtHeaderTypePDUSessionContainer, []byte{0x10, 0x09}, 0))
	plainOctets, _ := plain.Marshal()
	containerOctets, _ := container.Marshal()
	buffer := make([]byte, 2048)

	var result measured
	switch name {
	case "encode-plain":
		result = encode(plain, buffer, iterations)
	case "encode-container":
		result = encode(container, buffer, iterations)
	case "decode-plain":
		result = decode(plainOctets, iterations)
	case "decode-container":
		result = decode(containerOctets, iterations)
	case "round-trip":
		result = roundTrip(payload, iterations)
	default:
		panic("no case " + name)
	}
	per := func(total uint64) float64 { return float64(total) / float64(iterations) }
	fmt.Printf("%s %d %.1f %.2f %.1f %d\n", name, iterations,
		float64(result.elapsed.Nanoseconds())/float64(iterations),
		per(result.allocations), per(result.octets), maxRSS())
}

func encode(header *message.Header, buffer []byte, iterations int) measured {
	m := start()
	for i := 0; i < iterations; i++ {
		header.SetLength()
		if err := header.MarshalTo(buffer[:header.MarshalLen()]); err != nil {
			panic(err)
		}
		sink += header.MarshalLen()
	}
	return m.stop()
}

func decode(octets []byte, iterations int) measured {
	m := start()
	for i := 0; i < iterations; i++ {
		header, err := message.ParseHeader(octets)
		if err != nil {
			panic(err)
		}
		sink += len(header.Payload)
	}
	return m.stop()
}

// A connection on a free port of 127.0.0.1, serving.
func listen() (*gtpv1.UPlaneConn, net.Addr) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	address := probe.LocalAddr()
	probe.Close()
	conn := gtpv1.NewUPlaneConn(address)
	conn.DisableErrorIndication()
	go func() {
		if err := conn.ListenAndServe(context.Background()); err != nil {
			panic(err)
		}
	}()
	return conn, address
}

// G-PDUs from one connection to another over the loopback interface, which
// sends each back.
func roundTrip(payload []byte, iterations int) measured {
	gnb, _ := listen()
	upf, upfAddress := listen()
	// Until both serve: the first G-PDU comes back.
	time.Sleep(100 * time.Millisecond)
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, from, _, err := upf.ReadFromGTP(buffer)
			if err != nil {
				return
			}
			if _, err := upf.WriteToGTP(teid, buffer[:n], from); err != nil {
				panic(err)
			}
		}
	}()
	buffer := make([]byte, 2048)
	exchange := func() {
		if _, err := gnb.WriteToGTP(teid, payload, upfAddress); err != nil {
			panic(err)
		}
		n, _, _, err := gnb.ReadFromGTP(buffer)
		if err != nil {
			panic(err)
		}
		sink += n
	}
	exchange()
	m := start()
	for i := 0; i < iterations; i++ {
		exchange()
	}
	return m.stop()
}

// The most memory the process had, in KiB (VmHWM).
func maxRSS() uint64 {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(status), "\n") {
		if value, found := strings.CutPrefix(line, "VmHWM:"); found {
			value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "kB"))
			kib, _ := strconv.ParseUint(value, 10, 64)
			return kib
		}
	}
	return 0
}
