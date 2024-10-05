//go:build linux
// +build linux

package wglinux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var _ wginternal.Client = &Client{}

// A Client provides access to Linux WireGuard netlink information.
type Client struct {
	c      *genetlink.Conn
	family genetlink.Family

	interfaces func() ([]string, error)
}

// New creates a new Client and returns whether or not the generic netlink
// interface is available.
func New() (*Client, bool, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, false, err
	}

	// Best effort version of netlink.Config.Strict due to CentOS 7.
	for _, o := range []netlink.ConnOption{
		netlink.ExtendedAcknowledge,
		netlink.GetStrictCheck,
	} {
		_ = c.SetOption(o, true)
	}

	return initClient(c)
}

// initClient is the internal Client constructor used in some tests.
func initClient(c *genetlink.Conn) (*Client, bool, error) {
	f, err := c.GetFamily(unix.WG_GENL_NAME)
	if err != nil {
		_ = c.Close()

		if errors.Is(err, os.ErrNotExist) {
			// The generic netlink interface is not available.
			return nil, false, nil
		}

		return nil, false, err
	}

	return &Client{
		c:      c,
		family: f,

		// By default, gather only WireGuard interfaces using rtnetlink.
		interfaces: rtnlInterfaces,
	}, true, nil
}

// Close implements wginternal.Client.
func (c *Client) Close() error {
	return c.c.Close()
}

// Devices implements wginternal.Client.
func (c *Client) Devices() ([]*wgtypes.Device, error) {
	// By default, rtnetlink is used to fetch a list of all interfaces and then
	// filter that list to only find WireGuard interfaces.
	//
	// The remainder of this function assumes that any returned device from this
	// function is a valid WireGuard device.
	ifis, err := c.interfaces()
	if err != nil {
		return nil, err
	}

	ds := make([]*wgtypes.Device, 0, len(ifis))
	for _, ifi := range ifis {
		d, err := c.Device(ifi)
		if err != nil {
			return nil, err
		}

		ds = append(ds, d)
	}

	return ds, nil
}

// Device implements wginternal.Client.
func (c *Client) Device(name string) (*wgtypes.Device, error) {
	// Don't bother querying netlink with empty input.
	if name == "" {
		return nil, os.ErrNotExist
	}

	// Fetching a device by interface index is possible as well, but we only
	// support fetching by name as it seems to be more convenient in general.
	b, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(name),
	}})
	if err != nil {
		return nil, err
	}

	msgs, err := c.execute(unix.WG_CMD_GET_DEVICE, netlink.Request|netlink.Dump, b)
	if err != nil {
		return nil, err
	}

	return parseDevice(msgs)
}

// ConfigureDevice implements wginternal.Client.
func (c *Client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	// Large configurations are split into batches for use with netlink.
	for _, b := range buildBatches(cfg) {
		attrs, err := configAttrs(name, b)
		if err != nil {
			return err
		}

		// Request acknowledgement of our request from netlink, even though the
		// output messages are unused.  The netlink package checks and trims the
		// status code value.
		fmt.Println("yama_debug:EXECUTED: cfg:", cfg)
		fmt.Println("yama_debug:EXECUTED: attrs:", attrs)
		if _, err := c.execute(unix.WG_CMD_SET_DEVICE, netlink.Request|netlink.Acknowledge, attrs); err != nil {
			return err
		}
	}

	return nil
}

// execute executes a single WireGuard netlink request with the specified command,
// header flags, and attribute arguments.
func (c *Client) execute(command uint8, flags netlink.HeaderFlags, attrb []byte) ([]genetlink.Message, error) {
	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: command,
			Version: unix.WG_GENL_VERSION,
		},
		Data: attrb,
	}

	decodeAttributes(msg)

	msgs, err := c.c.Execute(msg, c.family.ID, flags)
	if err == nil {
		return msgs, nil
	}

	// We don't want to expose netlink errors directly to callers so unpack to
	// something more generic.
	oerr, ok := err.(*netlink.OpError)
	if !ok {
		// Expect all errors to conform to netlink.OpError.
		return nil, fmt.Errorf("wglinux: netlink operation returned non-netlink error (please file a bug: https://golang.zx2c4.com/wireguard/wgctrl): %v", err)
	}

	switch oerr.Err {
	// Convert "no such device" and "not a wireguard device" to an error
	// compatible with os.ErrNotExist for easy checking.
	case unix.ENODEV, unix.ENOTSUP:
		return nil, os.ErrNotExist
	default:
		// Expose the inner error directly (such as EPERM).
		return nil, oerr.Err
	}
}

func decodeAttributes(msg genetlink.Message) error {
	ad, err := netlink.NewAttributeDecoder(msg.Data)
	if err != nil {
		return fmt.Errorf("failed to create attribute decoder: %v", err)
	}

	for ad.Next() {
		switch ad.Type() {
		case unix.WGDEVICE_A_IFNAME:
			ifname := ad.String()
			fmt.Printf("yama: Interface Name: %s\n", ifname)
		case unix.WGDEVICE_A_LISTEN_PORT:
			listenPort := ad.Uint16()
			fmt.Printf("yama: Listen Port: %d\n", listenPort)
		case unix.WGDEVICE_A_PEERS:
			fmt.Println("yama: Peers:")
			parsePeers(ad.Bytes())
		default:
			fmt.Printf("yama: Unknown Attribute Type: %d, Value: %v\n", ad.Type(), ad.Bytes())
		}
	}

	if err := ad.Err(); err != nil {
		return fmt.Errorf("failed to decode attributes: %v", err)
	}

	return nil
}

func parsePeers(data []byte) {
	// data は WGDEVICE_A_PEERS 属性のデータであり、複数のピア属性を含む
	attrs, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		fmt.Printf("yama: Failed to unmarshal peers attributes: %v\n", err)
		return
	}

	for _, attr := range attrs {
		if attr.Type != unix.WGPEER_A_UNSPEC {
			parsePeer2(attr.Data)
		} else {
			fmt.Println("yama: Peer: unspec")
		}
	}
}

func parsePeer2(data []byte) {
	fmt.Println("yama: parsePeer2:")
	attrs, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		fmt.Printf("yama: Failed to unmarshal peer attributes: %v\n", err)
		return
	}

	for _, attr := range attrs {
		switch attr.Type {
		case unix.WGPEER_A_PUBLIC_KEY:
			publicKey := attr.Data
			fmt.Printf("yama:   Peer Public Key: %x\n", publicKey)
		case unix.WGPEER_A_PRESHARED_KEY:
			presharedKey := attr.Data
			fmt.Printf("yama:   Peer Preshared Key: %x\n", presharedKey)
		case unix.WGPEER_A_ENDPOINT:
			endpoint := attr.Data
			fmt.Printf("yama:   Peer Endpoint: %v\n", endpoint)
		case unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
			if len(attr.Data) >= 2 {
				keepaliveInterval := binary.LittleEndian.Uint16(attr.Data)
				fmt.Printf("yama:   Persistent Keepalive Interval: %d seconds\n", keepaliveInterval)
			}
		case unix.WGPEER_A_LAST_HANDSHAKE_TIME:
			handshakeTimeData := attr.Data
			fmt.Printf("yama:   Last Handshake Time: %v\n", handshakeTimeData)
		case unix.WGPEER_A_RX_BYTES:
			if len(attr.Data) >= 8 {
				rxBytes := binary.LittleEndian.Uint64(attr.Data)
				fmt.Printf("yama:   Received Bytes: %d\n", rxBytes)
			}
		case unix.WGPEER_A_TX_BYTES:
			if len(attr.Data) >= 8 {
				txBytes := binary.LittleEndian.Uint64(attr.Data)
				fmt.Printf("yama:   Transmitted Bytes: %d\n", txBytes)
			}
		case unix.WGPEER_A_ALLOWEDIPS:
			fmt.Println("yama:  Allowed IPs:")
		case unix.WGPEER_A_PROTOCOL_VERSION:
			if len(attr.Data) >= 4 {
				protocolVersion := binary.LittleEndian.Uint32(attr.Data)
				fmt.Printf("yama:   Protocol Version: %d\n", protocolVersion)
			}
		default:
			fmt.Printf("yama:   Unknown Peer Attribute Type: %d, Value: %v\n", attr.Type, attr.Data)
		}
	}
}

// rtnlInterfaces uses rtnetlink to fetch a list of WireGuard interfaces.
func rtnlInterfaces() ([]string, error) {
	// Use the stdlib's rtnetlink helpers to get ahold of a table of all
	// interfaces, so we can begin filtering it down to just WireGuard devices.
	tab, err := syscall.NetlinkRIB(unix.RTM_GETLINK, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("wglinux: failed to get list of interfaces from rtnetlink: %v", err)
	}

	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, fmt.Errorf("wglinux: failed to parse rtnetlink messages: %v", err)
	}

	return parseRTNLInterfaces(msgs)
}

// parseRTNLInterfaces unpacks rtnetlink messages and returns WireGuard
// interface names.
func parseRTNLInterfaces(msgs []syscall.NetlinkMessage) ([]string, error) {
	var ifis []string
	for _, m := range msgs {
		// Only deal with link messages, and they must have an ifinfomsg
		// structure appear before the attributes.
		if m.Header.Type != unix.RTM_NEWLINK {
			continue
		}

		if len(m.Data) < unix.SizeofIfInfomsg {
			return nil, fmt.Errorf("wglinux: rtnetlink message is too short for ifinfomsg: %d", len(m.Data))
		}

		ad, err := netlink.NewAttributeDecoder(m.Data[syscall.SizeofIfInfomsg:])
		if err != nil {
			return nil, err
		}

		// Determine the interface's name and if it's a WireGuard device.
		var (
			ifi  string
			isWG bool
		)

		for ad.Next() {
			switch ad.Type() {
			case unix.IFLA_IFNAME:
				ifi = ad.String()
			case unix.IFLA_LINKINFO:
				ad.Do(isWGKind(&isWG))
			}
		}

		if err := ad.Err(); err != nil {
			return nil, err
		}

		if isWG {
			// Found one; append it to the list.
			ifis = append(ifis, ifi)
		}
	}

	return ifis, nil
}

// wgKind is the IFLA_INFO_KIND value for WireGuard devices.
const wgKind = "wireguard"

// isWGKind parses netlink attributes to determine if a link is a WireGuard
// device, then populates ok with the result.
func isWGKind(ok *bool) func(b []byte) error {
	return func(b []byte) error {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return err
		}

		for ad.Next() {
			if ad.Type() != unix.IFLA_INFO_KIND {
				continue
			}

			if ad.String() == wgKind {
				*ok = true
				return nil
			}
		}

		return ad.Err()
	}
}
