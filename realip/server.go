package realip

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/go-kratos/kratos/v3/middleware"
	"github.com/go-kratos/kratos/v3/transport/http"
)

const (
	DefaultXFFHeader = "X-Forwarded-For"
)

type RealIP struct {
	logger    *slog.Logger
	headers   []string
	recursive bool
	trusts    []*net.IPNet
}

func New(opts ...Option) *RealIP {
	r := &RealIP{
		logger:    slog.Default().With("component", "middleware/realip"),
		headers:   []string{DefaultXFFHeader},
		recursive: true,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

type Option func(o *RealIP)

func WithLogger(logger *slog.Logger) Option {
	return func(o *RealIP) {
		o.logger = logger.With(
			slog.String("component", "middleware/realip"),
		)
	}
}

func WithHeaders(headers ...string) Option {
	return func(o *RealIP) {
		if len(headers) != 0 {
			o.headers = headers
		}
	}
}

func WithTrustedProxies(proxies ...string) Option {
	return func(o *RealIP) {
		trusts, err := toCIDRs(proxies)
		if err != nil {
			panic(err)
		}
		o.trusts = trusts
	}
}

func WithRecursive(v bool) Option {
	return func(o *RealIP) {
		o.recursive = v
	}
}

func parseProxy(proxy string) (*net.IPNet, error) {
	if !strings.Contains(proxy, "/") {
		ip := net.ParseIP(proxy)
		if ip.To4() != nil {
			proxy += "/32"
		} else {
			proxy += "/128"
		}
	}

	_, cidr, err := net.ParseCIDR(proxy)
	return cidr, err
}

// toCIDRs 转换 ips 到 cidrs, 必须全部成功或者返回 error
func toCIDRs(ips []string) ([]*net.IPNet, error) {
	results := make([]*net.IPNet, 0, len(ips))
	for _, proxy := range ips {
		cidr, err := parseProxy(proxy)
		if err != nil {
			return nil, fmt.Errorf("parse proxy: %w, proxy: %s", err, proxy)
		}
		results = append(results, cidr)
	}
	return results, nil
}

// Server 返回 RealIP 中间件，将第一个不受信任的 IP 注入上下文
// 如果发生任何错误，打印 warn 日志不会中断请求链
func (r *RealIP) Server() middleware.Middleware {
	logger := r.logger

	return func(h middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			request, ok := http.RequestFromServerContext(ctx)
			if !ok {
				// 缺少 http request
				logger.WarnContext(ctx, "missing http request in context")
				return h(ctx, req)
			}

			host, _, err := net.SplitHostPort(request.RemoteAddr)
			if err != nil {
				logger.WarnContext(
					ctx, "failed to split host port",
					slog.String("remote_addr", request.RemoteAddr),
					slog.Any("reason", err),
				)
				return h(ctx, req)
			}

			// 检查 peer 是否被信任
			if !r.isTrustedProxy(host) {
				// 如果 peer 不被信任，将 peer 作为客户端 IP
				ctx = NewContext(ctx, host)
				return h(ctx, req)
			}

			// 依次解析 header
			var result string
			for _, key := range r.headers {
				value := request.Header.Get(key)
				result = r.parseXFF(value)
				if result != "" {
					break
				}
			}

			if result != "" {
				ctx = NewContext(ctx, result)
			}
			return h(ctx, req)
		}
	}
}

// isTrustedProxy 检查 proxy 是否被信任
func (r *RealIP) isTrustedProxy(proxy string) bool {
	trusts := r.trusts

	ip := net.ParseIP(proxy)
	if ip == nil {
		return false
	}
	for _, trust := range trusts {
		if trust.Contains(ip) {
			return true
		}
	}
	return false
}

// parseXFF 从 XFF value 解析并返回真实客户端 IP
// 提取失败返回空字符串
func (r *RealIP) parseXFF(xffValue string) string {
	var (
		recursive = r.recursive
	)

	if xffValue == "" {
		return ""
	}

	// 切分 IP
	ips := strings.Split(xffValue, ",")
	n := len(ips)
	if n == 0 {
		return ""
	}

	if !recursive {
		// 非递归模式，直接返回最后一个 IP 作为客户端 IP
		return strings.TrimSpace(ips[n-1])
	}

	// 递归模式，逆序验证 IP 是否受信任，将遇到的第一个非信任 IP 作为客户端 IP
	var last string
	for i := n - 1; i >= 0; i-- {
		last = strings.TrimSpace(ips[i])
		if !r.isTrustedProxy(last) {
			break
		}
	}
	return last
}

type realIPKey struct{}

func NewContext(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, realIPKey{}, ip)
}

func FromContext(ctx context.Context) (ip string, ok bool) {
	ip, ok = ctx.Value(realIPKey{}).(string)
	return
}

func Extractor(ctx context.Context) []slog.Attr {
	v, _ := FromContext(ctx)
	return []slog.Attr{
		slog.String("real_ip", v),
	}
}
