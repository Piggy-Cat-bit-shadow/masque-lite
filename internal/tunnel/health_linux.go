//go:build linux

package tunnel

import (
	"fmt"
	"net"
	"net/netip"
)

func CheckInterface(name string, expected netip.Prefix, mtu int) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("%s missing: %w", name, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("%s is down", name)
	}
	if iface.MTU != mtu {
		return fmt.Errorf("%s MTU mismatch: got %d want %d", name, iface.MTU, mtu)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("read %s addresses: %w", name, err)
	}
	for _, addr := range addrs {
		var prefix netip.Prefix
		switch value := addr.(type) {
		case *net.IPNet:
			parsed, ok := netip.AddrFromSlice(value.IP)
			if !ok {
				continue
			}
			bits, _ := value.Mask.Size()
			prefix = netip.PrefixFrom(parsed, bits)
		case *net.IPAddr:
			parsed, ok := netip.AddrFromSlice(value.IP)
			if !ok {
				continue
			}
			prefix = netip.PrefixFrom(parsed, parsed.BitLen())
		default:
			continue
		}
		if prefix == expected || (prefix.Addr() == expected.Addr() && prefix.Bits() == expected.Bits()) {
			return nil
		}
	}
	return fmt.Errorf("%s missing address %s", name, expected)
}
