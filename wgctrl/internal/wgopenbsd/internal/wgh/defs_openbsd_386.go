//go:build openbsd && 386
// +build openbsd,386

// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs defs.go

package wgh

const (
	SizeofIfgreq = 0x10
)

type Ifgroupreq struct {
	Name   [16]byte
	Len    uint32
	Pad1   [0]byte
	Groups *Ifgreq
	Pad2   [12]byte
}

type Ifgreq struct {
	Ifgrqu [16]byte
}

type Timespec struct {
	Sec  int64
	Nsec int32
}

type WGAIPIO struct {
	Af   uint8
	Cidr int32
	Addr [16]byte
}

type WGDataIO struct {
	Name      [16]byte
	Size      uint32
	Interface *WGInterfaceIO
}

type WGInterfaceIO struct {
	Flags       uint8
	Port        uint16
	Rtable      int32
	Public      [32]byte
	Private     [32]byte
	Peers_count uint32
}

type WGPeerIO struct {
	Flags            int32
	Protocol_version int32
	Public           [32]byte
	Psk              [32]byte
	Pka              uint16
	Pad_cgo_0        [2]byte
	Endpoint         [28]byte
	Txbytes          uint64
	Rxbytes          uint64
	Last_handshake   Timespec
	Aips_count       uint32
}

const (
	SIOCGWG = 0xc01869d3

	WG_INTERFACE_HAS_PUBLIC    = 0x1
	WG_INTERFACE_HAS_PRIVATE   = 0x2
	WG_INTERFACE_HAS_PORT      = 0x4
	WG_INTERFACE_HAS_RTABLE    = 0x8
	WG_INTERFACE_REPLACE_PEERS = 0x10

	WG_PEER_HAS_PUBLIC   = 0x1
	WG_PEER_HAS_PSK      = 0x2
	WG_PEER_HAS_PKA      = 0x4
	WG_PEER_HAS_ENDPOINT = 0x8

	SizeofWGAIPIO       = 0x18
	SizeofWGInterfaceIO = 0x4c
	SizeofWGPeerIO      = 0x88
)
