package buildkitrunner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"
)

const gatewayService = "moby.buildkit.v1.frontend.LLBBridge"
const buildHeader = "buildkit-controlapi-buildid"
const maxMessageBytes = 64 << 20

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func dialUpgrade(ctx context.Context, opts Options, path string, headers http.Header) (net.Conn, error) {
	target, err := url.Parse(opts.Host)
	if err != nil {
		return nil, fmt.Errorf("parse proxy host: %w", err)
	}
	if target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return nil, errors.New("proxy host cannot contain credentials, query, or fragment")
	}
	network, address := "tcp", target.Host
	switch target.Scheme {
	case "unix":
		if target.Host != "" || !strings.HasPrefix(target.Path, "/") {
			return nil, errors.New("unix proxy host requires an absolute socket path")
		}
		network, address = "unix", target.Path
	case "http", "https":
		if target.Hostname() == "" || (target.Path != "" && target.Path != "/") {
			return nil, errors.New("HTTP proxy host must contain only scheme and authority")
		}
		if target.Port() == "" {
			port := "80"
			if target.Scheme == "https" {
				port = "443"
			}
			address = net.JoinHostPort(target.Hostname(), port)
		}
	default:
		return nil, errors.New("proxy host must use unix://, http://, or https://")
	}
	if target.Scheme != "https" && (opts.CAFile != "" || opts.CertFile != "" || opts.KeyFile != "") {
		return nil, errors.New("TLS files require an https proxy host")
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(handshakeCtx, network, address)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy: %w", err)
	}
	success := false
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	rawConn := conn
	stop := context.AfterFunc(handshakeCtx, func() { rawConn.Close() })
	defer stop()
	deadline, _ := handshakeCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if target.Scheme == "https" {
		config, err := clientTLSConfig(opts, target.Hostname())
		if err != nil {
			return nil, err
		}
		secure := tls.Client(conn, config)
		if err := secure.HandshakeContext(handshakeCtx); err != nil {
			return nil, fmt.Errorf("proxy TLS handshake: %w", err)
		}
		conn = secure
	}
	req, err := http.NewRequestWithContext(handshakeCtx, http.MethodPost, "http://sockguard"+path, nil)
	if err != nil {
		return nil, err
	}
	if target.Host != "" {
		req.Host = target.Host
	}
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "h2c")
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("write proxy upgrade: %w", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, fmt.Errorf("read proxy upgrade: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(response.Header.Get("Upgrade"), "h2c") {
		response.Body.Close()
		return nil, fmt.Errorf("proxy refused %s upgrade: %s", path, response.Status)
	}
	if !stop() || handshakeCtx.Err() != nil {
		return nil, handshakeCtx.Err()
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	success = true
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

func clientTLSConfig(opts Options, host string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, NextProtos: []string{"http/1.1"}}
	if (opts.CertFile == "") != (opts.KeyFile == "") {
		return nil, errors.New("TLS client certificate and key must be supplied together")
	}
	if opts.CAFile != "" {
		data, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("TLS CA file contains no certificates")
		}
		config.RootCAs = roots
	}
	if opts.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{cert}
	}
	return config, nil
}

func readMessage(src io.Reader) ([]byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(src, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[1:])
	if header[0] != 0 || size > maxMessageBytes-5 {
		return nil, errors.New("invalid or oversized uncompressed gRPC frame")
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(src, data); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, err := io.ReadFull(src, extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return nil, errors.New("expected one unary gRPC message")
	}
	return data, nil
}

func frameMessage(payload []byte) []byte {
	length := int64(len(payload))
	if length > maxMessageBytes-5 || length > math.MaxUint32 {
		return nil
	}
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:5], uint32(length))
	copy(frame[5:], payload)
	return frame
}

func unary(ctx context.Context, client *http2.ClientConn, path, build string, message proto.Message) ([]byte, error) {
	payload, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}
	frame := frameMessage(payload)
	if frame == nil {
		return nil, errors.New("gateway request exceeds size cap")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://sockguard"+path, bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	if build != "" {
		req.Header.Set(buildHeader, build)
	}
	resp, err := client.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, readErr := readMessage(resp.Body)
	if err := responseStatus(resp); err != nil {
		return nil, err
	}
	if readErr != nil {
		return nil, readErr
	}
	return data, nil
}

func responseStatus(resp *http.Response) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway HTTP status: %s", resp.Status)
	}
	status := resp.Trailer.Get("Grpc-Status")
	if status == "" {
		status = resp.Header.Get("Grpc-Status")
	}
	if status != "0" {
		message := resp.Trailer.Get("Grpc-Message")
		if message == "" {
			message = resp.Header.Get("Grpc-Message")
		}
		if decoded, err := url.PathUnescape(message); err == nil {
			message = decoded
		}
		return fmt.Errorf("gateway RPC failed (%s): %s", status, message)
	}
	return nil
}
