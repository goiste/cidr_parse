package cidr_parse

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIpToUint32(t *testing.T) {
	tests := []struct {
		Name   string
		IP     string
		Result uint32
	}{
		{Name: "10.0.0.0", IP: "10.0.0.0", Result: 0xa000000},
		{Name: "127.0.0.1", IP: "127.0.0.1", Result: 0x7f000001},
		{Name: "255.255.255.255", IP: "255.255.255.255", Result: maskFull},
		{Name: "255.0.0.0", IP: "255.0.0.0", Result: maskFirst},
		{Name: "0.255.0.0", IP: "0.255.0.0", Result: maskSecond},
		{Name: "0.0.255.0", IP: "0.0.255.0", Result: maskThird},
		{Name: "0.0.0.255", IP: "0.0.0.255", Result: maskLast},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			res := ipToUint32(tt.IP)
			require.Equal(t, tt.Result, res)
		})
	}
}

func TestCIDRRange_New(t *testing.T) {
	tests := []struct {
		Name      string
		CIDR      string
		NeedError bool
	}{
		{Name: "empty_cidr", CIDR: "", NeedError: true},
		{Name: "invalid_cidr", CIDR: "10.0.0.0/33", NeedError: true},
		{Name: "invalid_string", CIDR: "test", NeedError: true},
		{Name: "valid_cidr", CIDR: "10.0.0.0/16", NeedError: false},
		{Name: "invalid_mask_size", CIDR: "2001:db8:0:160::/64", NeedError: true},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			_, err := NewCIDRParse(tt.CIDR, true)
			toggleError(t, err, tt.NeedError)
		})
	}
}

func TestCIDRRange_FirstIP(t *testing.T) {
	tests := []struct {
		Name        string
		CIDR        string
		IncludeZero bool
		FirstIP     string
	}{
		{Name: "10.0.0.0/16", CIDR: "10.0.0.0/16", IncludeZero: true, FirstIP: "10.0.0.0"},
		{Name: "10.0.0.0/16", CIDR: "10.0.0.0/16", FirstIP: "10.0.0.1"},
		{Name: "10.0.0.0/32", CIDR: "10.0.0.0/32", IncludeZero: true, FirstIP: "10.0.0.0"},
		{Name: "10.0.0.0/32", CIDR: "10.0.0.0/32", FirstIP: "10.0.0.1"},
		{Name: "10.0.0.127/32", CIDR: "10.0.0.127/32", FirstIP: "10.0.0.127"},
		{Name: "10.0.255.128/16", CIDR: "10.0.255.128/16", IncludeZero: true, FirstIP: "10.0.0.0"},
		{Name: "10.0.255.128/16", CIDR: "10.0.255.128/16", FirstIP: "10.0.0.1"},
		{Name: "10.0.255.128/24", CIDR: "10.0.255.128/24", IncludeZero: true, FirstIP: "10.0.255.0"},
		{Name: "10.0.255.128/24", CIDR: "10.0.255.128/24", FirstIP: "10.0.255.1"},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			r, err := NewCIDRParse(tt.CIDR, tt.IncludeZero)
			require.NoError(t, err)
			require.Equal(t, tt.FirstIP, r.FirstIP())
		})
	}
}

func TestCIDRRange_LastIP(t *testing.T) {
	tests := []struct {
		Name   string
		CIDR   string
		LastIP string
	}{
		{Name: "10.0.0.0/32", CIDR: "10.0.0.0/32", LastIP: "10.0.0.0"},
		{Name: "10.0.0.127/32", CIDR: "10.0.0.127/32", LastIP: "10.0.0.127"},
		{Name: "10.0.0.0/28", CIDR: "10.0.0.0/25", LastIP: "10.0.0.127"},
		{Name: "10.0.0.0/24", CIDR: "10.0.0.0/24", LastIP: "10.0.0.255"},
		{Name: "10.0.0.0/16", CIDR: "10.0.0.0/16", LastIP: "10.0.255.255"},
		{Name: "10.0.0.0/8", CIDR: "10.0.0.0/8", LastIP: "10.255.255.255"},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			r, err := NewCIDRParse(tt.CIDR, true)
			require.NoError(t, err)
			require.Equal(t, tt.LastIP, r.LastIP())
		})
	}
}

func TestCIDRRange_Len(t *testing.T) {
	tests := []struct {
		Name        string
		CIDR        string
		IncludeZero bool
		Len         int
	}{
		{Name: "10.0.0.0/32", CIDR: "10.0.0.0/32", IncludeZero: true, Len: 1},
		{Name: "10.0.0.0/32", CIDR: "10.0.0.0/32", Len: 0},
		{Name: "10.0.0.0/24", IncludeZero: true, CIDR: "10.0.0.0/24", Len: 256},
		{Name: "10.0.0.0/24", CIDR: "10.0.0.0/24", Len: 255},
		{Name: "10.0.0.0/16", CIDR: "10.0.0.0/16", IncludeZero: true, Len: 65536},
		{Name: "10.0.0.0/16", CIDR: "10.0.0.0/16", Len: 65535},
		{Name: "10.0.0.0/8", CIDR: "10.0.0.0/8", IncludeZero: true, Len: 16777216},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			r, err := NewCIDRParse(tt.CIDR, tt.IncludeZero)
			require.NoError(t, err)
			require.Equal(t, tt.Len, r.Len())
		})
	}
}

func TestCIDRRange_List(t *testing.T) {
	tests := []struct {
		Name      string
		CIDR      string
		ListCount int
	}{
		{Name: "10.0.0.0/32", CIDR: "10.0.0.0/32", ListCount: 1},
		{Name: "10.0.0.127/32", CIDR: "10.0.0.127/32", ListCount: 1},
		{Name: "10.0.0.0/28", CIDR: "10.0.0.0/25", ListCount: 128},
		{Name: "10.0.0.0/24", CIDR: "10.0.0.0/24", ListCount: 256},
		{Name: "10.0.0.0/19", CIDR: "10.0.0.0/19", ListCount: 8192},
		{Name: "10.0.0.0/16", CIDR: "10.0.0.0/16", ListCount: 65536},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			r, err := NewCIDRParse(tt.CIDR, true)
			require.NoError(t, err)
			require.Equal(t, tt.ListCount, len(r.List()))
		})
	}
}

func TestCIDRRange_NextIPFunc(t *testing.T) {
	tests := []struct {
		Name      string
		CIDR      string
		RunsCount int
		IsOk      bool
		IP        string
	}{
		{Name: "10.0.0.0/32", CIDR: "10.0.0.0/32", RunsCount: 1, IsOk: true, IP: "10.0.0.0"},
		{Name: "10.0.0.0/32", CIDR: "10.0.0.0/32", RunsCount: 2, IsOk: false, IP: "10.0.0.0"},
		{Name: "10.0.0.0/24", CIDR: "10.0.0.0/24", RunsCount: 1, IsOk: true, IP: "10.0.0.0"},
		{Name: "10.0.0.0/24", CIDR: "10.0.0.0/24", RunsCount: 42, IsOk: true, IP: "10.0.0.41"},
		{Name: "10.0.0.0/24", CIDR: "10.0.0.0/24", RunsCount: 256, IsOk: true, IP: "10.0.0.255"},
		{Name: "10.0.0.0/24", CIDR: "10.0.0.0/24", RunsCount: 257, IsOk: false, IP: "10.0.0.255"},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			r, err := NewCIDRParse(tt.CIDR, true)
			require.NoError(t, err)

			ip := ""
			ok := false

			next := r.NextIPFunc()
			for i := 0; i < tt.RunsCount; i++ {
				ip, ok = next()
			}
			require.Equal(t, tt.IsOk, ok)
			require.Equal(t, tt.IP, ip)
		})
	}
}

func toggleError(t *testing.T, err error, needError bool) {
	if needError {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
}
