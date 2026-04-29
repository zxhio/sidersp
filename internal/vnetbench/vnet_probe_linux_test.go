//go:build linux

package vnetbench

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	etherTypeIPv4 = 0x0800
	ipProtoICMP   = 1
	ipProtoTCP    = 6
	ethHeaderLen  = 14
	ipv4HeaderLen = 20
	icmpHeaderLen = 8
	tcpHeaderLen  = 20
	tcpFlagRST    = 0x04
	tcpFlagSYN    = 0x02
	tcpFlagACK    = 0x10
)

var probeICMPPayload = []byte("sidersp-loop-icmp")

type probeKind string

const (
	probeICMP probeKind = "icmp"
	probeSYN  probeKind = "syn"
	probeRST  probeKind = "rst"
)

type probeLoopResult struct {
	Count       int
	Successes   int
	Total       time.Duration
	Latencies   []time.Duration
	RequestSize int
}

type latencySummary struct {
	Count int
	Min   time.Duration
	Avg   time.Duration
	P50   time.Duration
	P95   time.Duration
	Max   time.Duration
}

type namespaceProbeConfig struct {
	NamespacePath string
	InterfaceName string
	PeerIP        netip.Addr
	HostIP        netip.Addr
	HostMAC       net.HardwareAddr
}

type probeRequest struct {
	kind       probeKind
	targetIP   netip.Addr
	tcpPort    uint16
	count      int
	timeout    time.Duration
	withSample bool
	resp       chan probeResponse
}

type probeResponse struct {
	result probeLoopResult
	err    error
}

type namespaceProbeRunner struct {
	cfg       namespaceProbeConfig
	requests  chan probeRequest
	closeOnce sync.Once
	done      chan struct{}
}

func newNamespaceProbeRunner(tb testingTB, cfg namespaceProbeConfig) *namespaceProbeRunner {
	tb.Helper()

	runner := &namespaceProbeRunner{
		cfg:      cfg,
		requests: make(chan probeRequest),
		done:     make(chan struct{}),
	}

	ready := make(chan error, 1)
	go runner.run(ready)
	if err := <-ready; err != nil {
		_ = runner.Close()
		tb.Fatalf("start namespace probe runner: %v", err)
	}

	tb.Cleanup(func() {
		if err := runner.Close(); err != nil {
			tb.Errorf("close namespace probe runner: %v", err)
		}
	})
	return runner
}

func (r *namespaceProbeRunner) RunICMPLoop(targetIP netip.Addr, count int, timeout time.Duration, withSample bool) (probeLoopResult, error) {
	return r.runLoop(probeICMP, targetIP, 0, count, timeout, withSample)
}

func (r *namespaceProbeRunner) RunSYNLoop(targetIP netip.Addr, tcpPort uint16, count int, timeout time.Duration, withSample bool) (probeLoopResult, error) {
	return r.runLoop(probeSYN, targetIP, tcpPort, count, timeout, withSample)
}

func (r *namespaceProbeRunner) RunRSTLoop(targetIP netip.Addr, tcpPort uint16, count int, timeout time.Duration, withSample bool) (probeLoopResult, error) {
	return r.runLoop(probeRST, targetIP, tcpPort, count, timeout, withSample)
}

func (r *namespaceProbeRunner) runLoop(kind probeKind, targetIP netip.Addr, tcpPort uint16, count int, timeout time.Duration, withSample bool) (probeLoopResult, error) {
	respCh := make(chan probeResponse, 1)
	req := probeRequest{
		kind:       kind,
		targetIP:   targetIP,
		tcpPort:    tcpPort,
		count:      count,
		timeout:    timeout,
		withSample: withSample,
		resp:       respCh,
	}

	select {
	case r.requests <- req:
	case <-r.done:
		return probeLoopResult{}, fmt.Errorf("probe runner is closed")
	}

	resp := <-respCh
	return resp.result, resp.err
}

func (r *namespaceProbeRunner) Close() error {
	var closeErr error
	r.closeOnce.Do(func() {
		close(r.requests)
		<-r.done
	})
	return closeErr
}

func (r *namespaceProbeRunner) run(ready chan<- error) {
	defer close(r.done)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	rootNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		ready <- fmt.Errorf("open root netns: %w", err)
		return
	}
	defer rootNS.Close()

	targetNS, err := os.Open(r.cfg.NamespacePath)
	if err != nil {
		ready <- fmt.Errorf("open target netns: %w", err)
		return
	}
	defer targetNS.Close()

	if err := unix.Setns(int(targetNS.Fd()), unix.CLONE_NEWNET); err != nil {
		ready <- fmt.Errorf("setns %s: %w", r.cfg.NamespacePath, err)
		return
	}
	defer func() {
		_ = unix.Setns(int(rootNS.Fd()), unix.CLONE_NEWNET)
	}()

	iface, err := net.InterfaceByName(r.cfg.InterfaceName)
	if err != nil {
		ready <- fmt.Errorf("lookup probe interface %s: %w", r.cfg.InterfaceName, err)
		return
	}

	fd, err := openPacketSocket(iface.Index)
	if err != nil {
		ready <- err
		return
	}
	defer unix.Close(fd)

	cfg := packetProbeConfig{
		PeerMAC: append(net.HardwareAddr(nil), iface.HardwareAddr...),
		HostMAC: append(net.HardwareAddr(nil), r.cfg.HostMAC...),
		PeerIP:  r.cfg.PeerIP,
		HostIP:  r.cfg.HostIP,
	}

	ready <- nil

	for req := range r.requests {
		var (
			result probeLoopResult
			runErr error
		)
		switch req.kind {
		case probeICMP:
			result, runErr = runICMPLoop(fd, cfg, req.targetIP, req.count, req.timeout, req.withSample)
		case probeSYN:
			result, runErr = runSYNLoop(fd, cfg, req.targetIP, req.tcpPort, req.count, req.timeout, req.withSample)
		case probeRST:
			result, runErr = runRSTLoop(fd, cfg, req.targetIP, req.tcpPort, req.count, req.timeout, req.withSample)
		default:
			panic(fmt.Sprintf("unreachable probe kind %q", req.kind))
		}
		req.resp <- probeResponse{result: result, err: runErr}
	}
}

type packetProbeConfig struct {
	PeerMAC net.HardwareAddr
	HostMAC net.HardwareAddr
	PeerIP  netip.Addr
	HostIP  netip.Addr
}

func openPacketSocket(ifindex int) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("open AF_PACKET probe socket: %w", err)
	}

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Ifindex:  ifindex,
		Protocol: htons(unix.ETH_P_ALL),
	}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind AF_PACKET probe socket to ifindex %d: %w", ifindex, err)
	}
	return fd, nil
}

func runICMPLoop(fd int, cfg packetProbeConfig, targetIP netip.Addr, count int, timeout time.Duration, withSample bool) (probeLoopResult, error) {
	recvBuf := make([]byte, 4096)
	if err := drainPacketSocket(fd, recvBuf); err != nil {
		return probeLoopResult{}, err
	}

	frame := make([]byte, ethHeaderLen+ipv4HeaderLen+icmpHeaderLen+len(probeICMPPayload))
	result := probeLoopResult{Count: count}
	if withSample {
		result.Latencies = make([]time.Duration, 0, count)
	}

	for i := 0; i < count; i++ {
		identifier := uint16(0x5300 + (i % 0xff))
		sequence := uint16(i + 1)
		if result.RequestSize == 0 {
			result.RequestSize = len(frame)
		}
		buildICMPEchoRequestFrame(frame, cfg.PeerMAC, cfg.HostMAC, cfg.PeerIP, targetIP, identifier, sequence, probeICMPPayload)

		startedAt := time.Now()
		if err := writePacketSocket(fd, frame); err != nil {
			return probeLoopResult{}, err
		}
		if err := readICMPEchoReply(fd, cfg, targetIP, identifier, sequence, timeout, recvBuf); err != nil {
			return probeLoopResult{}, err
		}

		latency := time.Since(startedAt)
		result.Successes++
		result.Total += latency
		if withSample {
			result.Latencies = append(result.Latencies, latency)
		}
	}

	return result, nil
}

func runSYNLoop(fd int, cfg packetProbeConfig, targetIP netip.Addr, tcpPort uint16, count int, timeout time.Duration, withSample bool) (probeLoopResult, error) {
	recvBuf := make([]byte, 4096)
	if err := drainPacketSocket(fd, recvBuf); err != nil {
		return probeLoopResult{}, err
	}

	synFrame := make([]byte, ethHeaderLen+ipv4HeaderLen+tcpHeaderLen)
	rstFrame := make([]byte, ethHeaderLen+ipv4HeaderLen+tcpHeaderLen)
	result := probeLoopResult{Count: count}
	if withSample {
		result.Latencies = make([]time.Duration, 0, count)
	}

	for i := 0; i < count; i++ {
		srcPort := uint16(30000 + (i % 20000))
		seq := uint32(0x5eed0000 + i*2)

		if result.RequestSize == 0 {
			result.RequestSize = len(synFrame)
		}
		buildTCPSYNFrame(synFrame, cfg.PeerMAC, cfg.HostMAC, cfg.PeerIP, targetIP, srcPort, tcpPort, seq)

		startedAt := time.Now()
		if err := writePacketSocket(fd, synFrame); err != nil {
			return probeLoopResult{}, err
		}

		reply, err := readTCPSYNACK(fd, cfg, targetIP, srcPort, tcpPort, seq, timeout, recvBuf)
		if err != nil {
			return probeLoopResult{}, err
		}

		buildTCPRSTAckFrame(rstFrame, cfg.PeerMAC, cfg.HostMAC, cfg.PeerIP, targetIP, srcPort, tcpPort, seq+1, reply.ServerSeq+1)
		if err := writePacketSocket(fd, rstFrame); err != nil {
			return probeLoopResult{}, err
		}

		latency := time.Since(startedAt)
		result.Successes++
		result.Total += latency
		if withSample {
			result.Latencies = append(result.Latencies, latency)
		}
	}

	return result, nil
}

func runRSTLoop(fd int, cfg packetProbeConfig, targetIP netip.Addr, tcpPort uint16, count int, timeout time.Duration, withSample bool) (probeLoopResult, error) {
	recvBuf := make([]byte, 4096)
	if err := drainPacketSocket(fd, recvBuf); err != nil {
		return probeLoopResult{}, err
	}

	synFrame := make([]byte, ethHeaderLen+ipv4HeaderLen+tcpHeaderLen)
	result := probeLoopResult{Count: count}
	if withSample {
		result.Latencies = make([]time.Duration, 0, count)
	}

	for i := 0; i < count; i++ {
		srcPort := uint16(30000 + (i % 20000))
		seq := uint32(0x5eed0000 + i*2)

		if result.RequestSize == 0 {
			result.RequestSize = len(synFrame)
		}
		buildTCPSYNFrame(synFrame, cfg.PeerMAC, cfg.HostMAC, cfg.PeerIP, targetIP, srcPort, tcpPort, seq)

		startedAt := time.Now()
		if err := writePacketSocket(fd, synFrame); err != nil {
			return probeLoopResult{}, err
		}
		if err := readTCPReset(fd, cfg, targetIP, srcPort, tcpPort, seq, timeout, recvBuf); err != nil {
			return probeLoopResult{}, err
		}

		latency := time.Since(startedAt)
		result.Successes++
		result.Total += latency
		if withSample {
			result.Latencies = append(result.Latencies, latency)
		}
	}

	return result, nil
}

func writePacketSocket(fd int, frame []byte) error {
	if _, err := unix.Write(fd, frame); err != nil {
		return fmt.Errorf("send probe frame: %w", err)
	}
	return nil
}

func drainPacketSocket(fd int, buf []byte) error {
	pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}

	for {
		n, err := unix.Poll(pollFDs, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("poll probe socket: %w", err)
		}
		if n == 0 || pollFDs[0].Revents&unix.POLLIN == 0 {
			return nil
		}
		if _, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return nil
			}
			return fmt.Errorf("drain probe socket: %w", err)
		}
	}
}

func readICMPEchoReply(fd int, cfg packetProbeConfig, targetIP netip.Addr, identifier, sequence uint16, timeout time.Duration, recvBuf []byte) error {
	targetIPv4 := targetIP.As4()
	peerIPv4 := cfg.PeerIP.As4()
	return readMatchingFrame(fd, timeout, recvBuf, func(frame []byte) (bool, error) {
		if len(frame) < ethHeaderLen+ipv4HeaderLen+icmpHeaderLen {
			return false, nil
		}
		if binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv4 {
			return false, nil
		}
		if !bytes.Equal(frame[6:12], cfg.HostMAC) || !bytes.Equal(frame[0:6], cfg.PeerMAC) {
			return false, nil
		}
		if frame[ethHeaderLen] != 0x45 || frame[ethHeaderLen+9] != ipProtoICMP {
			return false, nil
		}
		if !bytes.Equal(frame[ethHeaderLen+12:ethHeaderLen+16], targetIPv4[:]) || !bytes.Equal(frame[ethHeaderLen+16:ethHeaderLen+20], peerIPv4[:]) {
			return false, nil
		}
		icmpOff := ethHeaderLen + ipv4HeaderLen
		if frame[icmpOff] != 0 || frame[icmpOff+1] != 0 {
			return false, nil
		}
		if binary.BigEndian.Uint16(frame[icmpOff+4:icmpOff+6]) != identifier || binary.BigEndian.Uint16(frame[icmpOff+6:icmpOff+8]) != sequence {
			return false, nil
		}
		return true, nil
	})
}

type synAckReply struct {
	ServerSeq uint32
}

func readTCPSYNACK(fd int, cfg packetProbeConfig, targetIP netip.Addr, srcPort, dstPort uint16, seq uint32, timeout time.Duration, recvBuf []byte) (synAckReply, error) {
	var reply synAckReply
	targetIPv4 := targetIP.As4()
	peerIPv4 := cfg.PeerIP.As4()
	err := readMatchingFrame(fd, timeout, recvBuf, func(frame []byte) (bool, error) {
		if len(frame) < ethHeaderLen+ipv4HeaderLen+tcpHeaderLen {
			return false, nil
		}
		if binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv4 {
			return false, nil
		}
		if !bytes.Equal(frame[6:12], cfg.HostMAC) || !bytes.Equal(frame[0:6], cfg.PeerMAC) {
			return false, nil
		}
		if frame[ethHeaderLen] != 0x45 || frame[ethHeaderLen+9] != ipProtoTCP {
			return false, nil
		}
		if !bytes.Equal(frame[ethHeaderLen+12:ethHeaderLen+16], targetIPv4[:]) || !bytes.Equal(frame[ethHeaderLen+16:ethHeaderLen+20], peerIPv4[:]) {
			return false, nil
		}
		tcpOff := ethHeaderLen + ipv4HeaderLen
		if binary.BigEndian.Uint16(frame[tcpOff:tcpOff+2]) != dstPort || binary.BigEndian.Uint16(frame[tcpOff+2:tcpOff+4]) != srcPort {
			return false, nil
		}
		flags := frame[tcpOff+13]
		if flags&(tcpFlagSYN|tcpFlagACK) != (tcpFlagSYN | tcpFlagACK) {
			return false, nil
		}
		if flags&tcpFlagRST != 0 || binary.BigEndian.Uint32(frame[tcpOff+8:tcpOff+12]) != seq+1 {
			return false, nil
		}

		reply.ServerSeq = binary.BigEndian.Uint32(frame[tcpOff+4 : tcpOff+8])
		return true, nil
	})
	return reply, err
}

func readTCPReset(fd int, cfg packetProbeConfig, targetIP netip.Addr, srcPort, dstPort uint16, seq uint32, timeout time.Duration, recvBuf []byte) error {
	targetIPv4 := targetIP.As4()
	peerIPv4 := cfg.PeerIP.As4()
	return readMatchingFrame(fd, timeout, recvBuf, func(frame []byte) (bool, error) {
		if len(frame) < ethHeaderLen+ipv4HeaderLen+tcpHeaderLen {
			return false, nil
		}
		if binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv4 {
			return false, nil
		}
		if !bytes.Equal(frame[6:12], cfg.HostMAC) || !bytes.Equal(frame[0:6], cfg.PeerMAC) {
			return false, nil
		}
		if frame[ethHeaderLen] != 0x45 || frame[ethHeaderLen+9] != ipProtoTCP {
			return false, nil
		}
		if !bytes.Equal(frame[ethHeaderLen+12:ethHeaderLen+16], targetIPv4[:]) || !bytes.Equal(frame[ethHeaderLen+16:ethHeaderLen+20], peerIPv4[:]) {
			return false, nil
		}
		tcpOff := ethHeaderLen + ipv4HeaderLen
		if binary.BigEndian.Uint16(frame[tcpOff:tcpOff+2]) != dstPort || binary.BigEndian.Uint16(frame[tcpOff+2:tcpOff+4]) != srcPort {
			return false, nil
		}
		flags := frame[tcpOff+13]
		if flags&(tcpFlagRST|tcpFlagACK) != (tcpFlagRST|tcpFlagACK) || flags&tcpFlagSYN != 0 {
			return false, nil
		}
		if binary.BigEndian.Uint32(frame[tcpOff+8:tcpOff+12]) != seq+1 {
			return false, nil
		}
		return true, nil
	})
}

func readMatchingFrame(fd int, timeout time.Duration, recvBuf []byte, matcher func([]byte) (bool, error)) error {
	deadline := time.Now().Add(timeout)
	pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("probe timeout after %s", timeout)
		}

		timeoutMS := int(remaining / time.Millisecond)
		if timeoutMS == 0 {
			timeoutMS = 1
		}

		n, err := unix.Poll(pollFDs, timeoutMS)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("poll probe socket: %w", err)
		}
		if n == 0 || pollFDs[0].Revents&unix.POLLIN == 0 {
			continue
		}

		size, _, err := unix.Recvfrom(fd, recvBuf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("read probe frame: %w", err)
		}

		match, err := matcher(recvBuf[:size])
		if err != nil {
			return err
		}
		if match {
			return nil
		}
	}
}

func buildICMPEchoRequestFrame(frame []byte, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP netip.Addr, identifier, sequence uint16, payload []byte) {
	buildEthernetHeader(frame, srcMAC, dstMAC)
	ip4 := frame[ethHeaderLen : ethHeaderLen+ipv4HeaderLen]
	buildIPv4Header(ip4, srcIP, dstIP, ipProtoICMP, icmpHeaderLen+len(payload))

	icmp := frame[ethHeaderLen+ipv4HeaderLen:]
	icmp[0] = 8
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[2:4], 0)
	binary.BigEndian.PutUint16(icmp[4:6], identifier)
	binary.BigEndian.PutUint16(icmp[6:8], sequence)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp[:icmpHeaderLen+len(payload)]))
}

func buildTCPSYNFrame(frame []byte, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seq uint32) {
	buildEthernetHeader(frame, srcMAC, dstMAC)
	ip4 := frame[ethHeaderLen : ethHeaderLen+ipv4HeaderLen]
	buildIPv4Header(ip4, srcIP, dstIP, ipProtoTCP, tcpHeaderLen)

	tcp := frame[ethHeaderLen+ipv4HeaderLen:]
	buildTCPHeader(tcp, srcPort, dstPort, seq, 0, tcpFlagSYN, 65535)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(ip4, tcp))
}

func buildTCPRSTAckFrame(frame []byte, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seq, ack uint32) {
	buildEthernetHeader(frame, srcMAC, dstMAC)
	ip4 := frame[ethHeaderLen : ethHeaderLen+ipv4HeaderLen]
	buildIPv4Header(ip4, srcIP, dstIP, ipProtoTCP, tcpHeaderLen)

	tcp := frame[ethHeaderLen+ipv4HeaderLen:]
	buildTCPHeader(tcp, srcPort, dstPort, seq, ack, tcpFlagRST|tcpFlagACK, 0)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(ip4, tcp))
}

func buildEthernetHeader(frame []byte, srcMAC, dstMAC net.HardwareAddr) {
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
}

func buildIPv4Header(ip4 []byte, srcIP, dstIP netip.Addr, proto uint8, payloadLen int) {
	ip4[0] = 0x45
	ip4[1] = 0
	binary.BigEndian.PutUint16(ip4[2:4], uint16(ipv4HeaderLen+payloadLen))
	binary.BigEndian.PutUint16(ip4[4:6], 0)
	binary.BigEndian.PutUint16(ip4[6:8], 0)
	ip4[8] = 64
	ip4[9] = proto
	binary.BigEndian.PutUint16(ip4[10:12], 0)
	copy(ip4[12:16], srcIP.AsSlice())
	copy(ip4[16:20], dstIP.AsSlice())
	binary.BigEndian.PutUint16(ip4[10:12], internetChecksum(ip4[:ipv4HeaderLen]))
}

func buildTCPHeader(tcp []byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16) {
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], window)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[18:20], 0)
}

func tcpChecksum(ip4 []byte, tcp []byte) uint16 {
	sum := checksumWords(ip4[12:20])
	sum += uint32(ipProtoTCP)
	sum += uint32(len(tcp))
	sum += checksumWords(tcp)
	return finalizeChecksum(sum)
}

func internetChecksum(data []byte) uint16 {
	return finalizeChecksum(checksumWords(data))
}

func checksumWords(data []byte) uint32 {
	var sum uint32
	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	return sum
}

func finalizeChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func summarizeLatencies(latencies []time.Duration) latencySummary {
	if len(latencies) == 0 {
		return latencySummary{}
	}

	sorted := append([]time.Duration(nil), latencies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var total time.Duration
	for _, sample := range sorted {
		total += sample
	}

	return latencySummary{
		Count: len(sorted),
		Min:   sorted[0],
		Avg:   total / time.Duration(len(sorted)),
		P50:   percentileDuration(sorted, 50),
		P95:   percentileDuration(sorted, 95),
		Max:   sorted[len(sorted)-1],
	}
}

func percentileDuration(sorted []time.Duration, percentile int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if percentile <= 0 {
		return sorted[0]
	}
	if percentile >= 100 {
		return sorted[len(sorted)-1]
	}

	index := (len(sorted)*percentile - 1) / 100
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func formatDurationMS(value time.Duration) string {
	return fmt.Sprintf("%.3f", float64(value)/float64(time.Millisecond))
}

func htons(v uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return binary.LittleEndian.Uint16(buf[:])
}
