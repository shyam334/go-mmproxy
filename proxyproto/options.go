package proxyproto

import (
	"net"
	"time"

	"go.uber.org/zap"
)

type Options struct {
	Protocol           string
	ListenAddr         string
	TargetAddr4        string
	TargetAddr6        string
	Mark               int
	Verbose            int
	AllowedSubnetsPath string
	AllowedSubnets     []*net.IPNet
	Listeners          int
	Logger             *zap.Logger
	UdpCloseAfterSec   int
	UDPCloseAfter      time.Duration
}
