package cidr_parse

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	maskFull   = 0xffffffff
	maskFirst  = 0xff000000
	maskSecond = 0x00ff0000
	maskThird  = 0x0000ff00
	maskLast   = 0x000000ff

	maskShiftFirst  = 24
	maskShiftSecond = 16
	maskShiftThird  = 8
)

// CIDRParse converts CIDR to the range of IPs (v4 only in this version)
type CIDRParse struct {
	firstIP uint32
	lastIP  uint32
}

func NewCIDRParse(cidr string, includeFirstZero bool) (*CIDRParse, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("error parsing CIDR %q: %w", cidr, err)
	}

	bits, size := ipNet.Mask.Size()
	if size != 32 {
		return nil, fmt.Errorf("unsupported mask size: %d", size)
	}

	zeroIP := ipToUint32(ipNet.IP.String())

	firstIP := zeroIP
	if !includeFirstZero && zeroIP&maskLast == 0 {
		firstIP++
	}

	lastIP := zeroIP | (maskFull >> bits)

	return &CIDRParse{
		firstIP: firstIP,
		lastIP:  lastIP,
	}, nil
}

// FirstIP is a first IP address of the range
func (r CIDRParse) FirstIP() string {
	return uint32ToIP(r.firstIP)
}

// LastIP is a last IP address of the range
func (r CIDRParse) LastIP() string {
	return uint32ToIP(r.lastIP)
}

// Len is a length of the range
func (r CIDRParse) Len() int {
	return int(r.lastIP - r.firstIP + 1)
}

// List returns all IPs as a string slice
func (r CIDRParse) List() []string {
	list := make([]string, 0, r.Len())
	next := r.NextIPFunc()
	ip, ok := next()
	for ok {
		list = append(list, ip)
		ip, ok = next()
	}
	return list
}

// NextIPFunc returns a generator function to iterate IPs one by one
func (r CIDRParse) NextIPFunc() func() (string, bool) {
	offset := uint32(0)
	return func() (string, bool) {
		ip := r.firstIP + offset
		var ok bool
		if ip > r.lastIP {
			ip = r.lastIP
		} else {
			offset++
			ok = true
		}
		return uint32ToIP(ip), ok
	}
}

// converts IP address string to uint32 number
func ipToUint32(ip string) uint32 {
	octets := make([]uint64, 4)
	for i, part := range strings.Split(ip, ".") {
		octets[i], _ = strconv.ParseUint(part, 10, 32)
	}

	return uint32(octets[0]<<maskShiftFirst | octets[1]<<maskShiftSecond | octets[2]<<maskShiftThird | octets[3])
}

// converts uint32 number to IP string
func uint32ToIP(ip uint32) string {
	return fmt.Sprintf(
		"%d.%d.%d.%d",
		ip&maskFirst>>maskShiftFirst,
		ip&maskSecond>>maskShiftSecond,
		ip&maskThird>>maskShiftThird,
		ip&maskLast,
	)
}
