package constant

import (
	"errors"
	"strings"
)

type BlockQuicMode int32

// BlockQuicModeMapping is a mapping for BlockQuicMode enum
var BlockQuicModeMapping = map[string]BlockQuicMode{
    BlockQuicModeAllProxy.String():    BlockQuicModeAllProxy,
    BlockQuicModeAll.String():         BlockQuicModeAll,
    BlockQuicModeAlwaysAllow.String(): BlockQuicModeAlwaysAllow,
}

const (
    BlockQuicModeAlwaysAllow BlockQuicMode = iota
    BlockQuicModeAllProxy
    BlockQuicModeAll
)

// UnmarshalText unserialize BlockQuicMode
func (m *BlockQuicMode) UnmarshalText(data []byte) error {
    mode, exist := BlockQuicModeMapping[strings.ToLower(string(data))]
    if !exist {
        return errors.New("invalid block-quic mode")
    }
    *m = mode
    return nil
}

// MarshalText serialize BlockQuicMode
func (m BlockQuicMode) MarshalText() ([]byte, error) {
    return []byte(m.String()), nil
}

func (m BlockQuicMode) String() string {
    switch m {
    case BlockQuicModeAllProxy:
        return "all-proxy"
    case BlockQuicModeAll:
        return "all"
    case BlockQuicModeAlwaysAllow:
        return "always-allow"
    default:
        return "unknown"
    }
}