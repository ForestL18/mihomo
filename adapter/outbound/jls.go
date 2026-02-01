package outbound

import "github.com/forestl18/mihomo/transport/jls"

type JLSOptions struct {
	Username string `proxy:"username"`
	Password string `proxy:"password"`
}

func (o JLSOptions) Parse() (*jls.Config, error) {
	if o.Username == "" && o.Password == "" {
		return nil, nil
	}
	return jls.NewConfig(o.Username, o.Password)
}
