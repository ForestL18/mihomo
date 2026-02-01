package restls

import (
	"context"
	"net"
	"runtime/debug"

	N "github.com/forestl18/mihomo/common/net"
	C "github.com/forestl18/mihomo/constant"
	LC "github.com/forestl18/mihomo/listener/config"
	"github.com/forestl18/mihomo/listener/inner"
	"github.com/forestl18/mihomo/log"
	"github.com/forestl18/mihomo/transport/restls"
)

type Builder struct {
	config *restls.ServerConfig
}

func New(config LC.ResTLS, tunnel C.Tunnel) *Builder {
	return &Builder{config: &restls.ServerConfig{
		ServerHostname: config.Dest,
		Password:       config.Password,
		RestlsScript:   config.RestlsScript,
		MinRecordLen:   config.MinRecordLen,
		RateLimit:      config.RateLimit,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return inner.HandleTcp(tunnel, address, config.Proxy)
		},
	}}
}

func (b Builder) NewListener(listener net.Listener) net.Listener {
	return N.NewHandleContextListener(context.Background(), listener, func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		return restls.Server(ctx, conn, b.config)
	}, func(a any) {
		stack := debug.Stack()
		log.Errorln("restls server panic: %s\n%s", a, stack)
	})
}
