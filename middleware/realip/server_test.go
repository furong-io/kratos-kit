package realip

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-kratos/kratos/v3/middleware"
	"github.com/go-kratos/kratos/v3/transport"
)

// fakeTransporter 实现 http.Transporter 接口，用于在测试中向 context 注入 *http.Request
type fakeTransporter struct {
	request *http.Request
}

func (f *fakeTransporter) Kind() transport.Kind            { return transport.KindHTTP }
func (f *fakeTransporter) Endpoint() string                { return "" }
func (f *fakeTransporter) Operation() string               { return "" }
func (f *fakeTransporter) RequestHeader() transport.Header { return nil }
func (f *fakeTransporter) ReplyHeader() transport.Header   { return nil }
func (f *fakeTransporter) Request() *http.Request          { return f.request }
func (f *fakeTransporter) PathTemplate() string            { return "" }

// discardLogger 返回一个不输出任何内容的 logger，避免测试日志干扰输出
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newRealIP 是 New 的测试封装，默认使用 discardLogger
func newRealIP(opts ...Option) *RealIP {
	return New(append([]Option{WithLogger(discardLogger())}, opts...)...)
}

// newTestContext 构造携带 http.Request 的 context，remoteAddr 为空时跳过 SplitHostPort 校验
func newTestContext(remoteAddr string, header http.Header) context.Context {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	if header != nil {
		req.Header = header
	}
	return transport.NewServerContext(context.Background(), &fakeTransporter{request: req})
}

// capturingHandler 记录传入的 context 供断言使用
func capturingHandler(captured *context.Context) middleware.Handler {
	return func(ctx context.Context, req any) (any, error) {
		*captured = ctx
		return nil, nil
	}
}

func TestParseProxy(t *testing.T) {
	cases := []struct {
		name    string
		proxy   string
		want    string
		wantErr bool
	}{
		{"ipv4 不带掩码", "192.168.1.1", "192.168.1.1/32", false},
		{"ipv4 带掩码", "10.0.0.0/8", "10.0.0.0/8", false},
		{"ipv6 不带掩码", "::1", "::1/128", false},
		{"非法 ip", "not-an-ip", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseProxy(c.proxy)
			if c.wantErr {
				if err == nil {
					t.Fatalf("期望返回 error，实际为 nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("意外的 error: %v", err)
			}
			if got.String() != c.want {
				t.Fatalf("got %s, want %s", got.String(), c.want)
			}
		})
	}
}

func TestToCIDRs(t *testing.T) {
	t.Run("全部成功", func(t *testing.T) {
		cidrs, err := toCIDRs([]string{"192.168.1.1", "10.0.0.0/8"})
		if err != nil {
			t.Fatalf("意外的 error: %v", err)
		}
		if len(cidrs) != 2 {
			t.Fatalf("期望 2 个 cidr，实际 %d 个", len(cidrs))
		}
	})

	t.Run("存在非法 ip 返回 error", func(t *testing.T) {
		_, err := toCIDRs([]string{"192.168.1.1", "not-an-ip"})
		if err == nil {
			t.Fatalf("期望返回 error，实际为 nil")
		}
	})
}

func TestIsTrustedProxy(t *testing.T) {
	r := newRealIP(WithTrustedProxies("10.0.0.0/8", "192.168.1.1"))

	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"落在 cidr 范围内", "10.1.2.3", true},
		{"精确匹配单个 ip", "192.168.1.1", true},
		{"不受信任", "8.8.8.8", false},
		{"非法 ip", "not-an-ip", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := r.isTrustedProxy(c.ip); got != c.want {
				t.Fatalf("isTrustedProxy(%q) = %v, want %v", c.ip, got, c.want)
			}
		})
	}
}

func TestParseXFF(t *testing.T) {
	trustedOpt := WithTrustedProxies("10.0.0.0/8")

	t.Run("空值返回空字符串", func(t *testing.T) {
		r := newRealIP(trustedOpt)
		if got := r.parseXFF(""); got != "" {
			t.Fatalf("got %q, want 空字符串", got)
		}
	})

	t.Run("非递归模式返回最后一个 ip", func(t *testing.T) {
		r := newRealIP(trustedOpt, WithRecursive(false))
		got := r.parseXFF("1.1.1.1, 10.0.0.1, 10.0.0.2")
		if got != "10.0.0.2" {
			t.Fatalf("got %q, want 10.0.0.2", got)
		}
	})

	t.Run("递归模式在第一个不受信任的 ip 处停止", func(t *testing.T) {
		r := newRealIP(trustedOpt, WithRecursive(true))
		got := r.parseXFF("8.8.8.8, 10.0.0.1, 10.0.0.2")
		if got != "8.8.8.8" {
			t.Fatalf("got %q, want 8.8.8.8", got)
		}
	})

	t.Run("递归模式下全部受信任返回最左侧 ip", func(t *testing.T) {
		r := newRealIP(trustedOpt, WithRecursive(true))
		got := r.parseXFF("10.0.0.1, 10.0.0.2")
		if got != "10.0.0.1" {
			t.Fatalf("got %q, want 10.0.0.1", got)
		}
	})
}

func TestContext(t *testing.T) {
	ctx := context.Background()
	if _, ok := FromContext(ctx); ok {
		t.Fatalf("空 context 期望 ok=false")
	}

	ctx = NewContext(ctx, "1.2.3.4")
	ip, ok := FromContext(ctx)
	if !ok || ip != "1.2.3.4" {
		t.Fatalf("got ip=%q ok=%v, want 1.2.3.4/true", ip, ok)
	}
}

func TestServer(t *testing.T) {
	t.Run("context 中缺少 http request 时直接放行", func(t *testing.T) {
		r := newRealIP(WithTrustedProxies("10.0.0.0/8"))
		var captured context.Context
		mw := r.Server()(capturingHandler(&captured))

		if _, err := mw(context.Background(), nil); err != nil {
			t.Fatalf("意外的 error: %v", err)
		}
		if _, ok := FromContext(captured); ok {
			t.Fatalf("期望 context 中没有 real ip")
		}
	})

	t.Run("remote addr 不合法时直接放行", func(t *testing.T) {
		r := newRealIP(WithTrustedProxies("10.0.0.0/8"))
		ctx := newTestContext("not-a-valid-addr", nil)
		var captured context.Context
		mw := r.Server()(capturingHandler(&captured))

		if _, err := mw(ctx, nil); err != nil {
			t.Fatalf("意外的 error: %v", err)
		}
		if _, ok := FromContext(captured); ok {
			t.Fatalf("期望 context 中没有 real ip")
		}
	})

	t.Run("peer 不受信任时使用 peer 自身 ip", func(t *testing.T) {
		r := newRealIP(WithTrustedProxies("10.0.0.0/8"))
		header := make(http.Header)
		header.Set(DefaultXFFHeader, "1.1.1.1")
		ctx := newTestContext("8.8.8.8:12345", header)
		var captured context.Context
		mw := r.Server()(capturingHandler(&captured))

		if _, err := mw(ctx, nil); err != nil {
			t.Fatalf("意外的 error: %v", err)
		}
		ip, ok := FromContext(captured)
		if !ok || ip != "8.8.8.8" {
			t.Fatalf("got ip=%q ok=%v, want 8.8.8.8/true", ip, ok)
		}
	})

	t.Run("peer 受信任时递归解析 header 得到真实 ip", func(t *testing.T) {
		r := newRealIP(WithTrustedProxies("10.0.0.0/8"), WithRecursive(true))
		header := make(http.Header)
		header.Set(DefaultXFFHeader, "8.8.8.8, 10.0.0.1, 10.0.0.2")
		ctx := newTestContext("10.0.0.2:12345", header)
		var captured context.Context
		mw := r.Server()(capturingHandler(&captured))

		if _, err := mw(ctx, nil); err != nil {
			t.Fatalf("意外的 error: %v", err)
		}
		ip, ok := FromContext(captured)
		if !ok || ip != "8.8.8.8" {
			t.Fatalf("got ip=%q ok=%v, want 8.8.8.8/true", ip, ok)
		}
	})

	t.Run("多个 header 按配置顺序取第一个非空结果", func(t *testing.T) {
		header := make(http.Header)
		header.Set("X-Real-IP", "9.9.9.9")
		r := newRealIP(
			WithTrustedProxies("10.0.0.0/8"),
			WithHeaders("X-Real-IP", DefaultXFFHeader),
			WithRecursive(false),
		)
		ctx := newTestContext("10.0.0.2:12345", header)
		var captured context.Context
		mw := r.Server()(capturingHandler(&captured))

		if _, err := mw(ctx, nil); err != nil {
			t.Fatalf("意外的 error: %v", err)
		}
		ip, ok := FromContext(captured)
		if !ok || ip != "9.9.9.9" {
			t.Fatalf("got ip=%q ok=%v, want 9.9.9.9/true", ip, ok)
		}
	})
}
