// Package identity handles application-scoped mutual TLS and local configuration.
package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

type User struct {
	ID             string `json:"id"`
	Role           string `json:"role"`
	Root           string `json:"root"`
	BytesPerSecond int64  `json:"bytes_per_second"`
	QuotaBytes     int64  `json:"quota_bytes"`
	Fingerprint    string `json:"fingerprint"`
}

type ServerConfig struct {
	Listen         string `json:"listen"`
	CertFile       string `json:"cert_file"`
	KeyFile        string `json:"key_file"`
	CAFile         string `json:"ca_file"`
	Users          []User `json:"users"`
	MaxConnections int    `json:"max_connections"`
	MaxFileBytes   int64  `json:"max_file_bytes"`
	AuditFile      string `json:"audit_file"`
}

type ClientConfig struct {
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	CAFile     string `json:"ca_file"`
	UIListen   string `json:"ui_listen"`
	Downloads  string `json:"downloads"`
}

const configLimit = 1 << 20

var identifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
var dnsLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func readConfig(path string, target any) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, configLimit+1))
	if err != nil {
		return "", err
	}
	if len(contents) > configLimit {
		return "", errors.New("配置文件超过 1 MiB")
	}
	if !json.Valid(contents) {
		return "", errors.New("配置文件不是有效的 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return "", fmt.Errorf("解析配置: %w", err)
	}
	return path, nil
}

// canonicalPath resolves the config-relative path and resolves aliases even if
// the final destination will only be created when the program starts.
func canonicalPath(directory, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("配置路径不能为空")
	}
	if !filepath.IsAbs(path) {
		if filepath.VolumeName(path) != "" || os.IsPathSeparator(path[0]) {
			return "", errors.New("配置路径必须是完整的绝对路径或一般相对路径")
		}
		path = filepath.Join(directory, path)
	}
	path = filepath.Clean(path)
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(path)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) || filepath.Dir(path) == path {
			return "", err
		}
		// A dangling symlink is not equivalent to a directory that may be created.
		if _, lstatErr := os.Lstat(path); !errors.Is(lstatErr, os.ErrNotExist) {
			return "", err
		}
		missing = append(missing, filepath.Base(path))
		path = filepath.Dir(path)
	}
}

func resolvePaths(directory string, paths ...*string) error {
	for _, field := range paths {
		path, err := canonicalPath(directory, *field)
		if err != nil {
			return err
		}
		*field = path
	}
	return nil
}

func inside(parent, child string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		parent, child = strings.ToLower(parent), strings.ToLower(child)
	}
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func splitAddress(addr string, zeroAllowed bool) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return "", errors.New("网络地址须为明确的主机地址与端口")
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || (!zeroAllowed && number == 0) {
		return "", errors.New("端口号无效")
	}
	return host, nil
}

func listenHost(address string, loopbackOnly, zeroAllowed bool) (string, error) {
	host, err := splitAddress(address, zeroAllowed)
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return "", errors.New("监听地址须为明确的 IP 地址")
	}
	ip = ip.Unmap()
	if !ip.IsLoopback() && (loopbackOnly || !ip.IsPrivate()) {
		if loopbackOnly {
			return "", errors.New("本地浏览器界面只允许监听回环地址")
		}
		return "", errors.New("文件服务只允许监听回环或指定的私有局域网地址")
	}
	return host, nil
}

func validHostName(name string) bool {
	if ip, err := netip.ParseAddr(name); err == nil {
		return ip.Zone() == ""
	}
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func LoadServer(path string) (ServerConfig, error) {
	var config ServerConfig
	path, err := readConfig(path, &config)
	if err != nil {
		return ServerConfig{}, err
	}
	if _, err := listenHost(config.Listen, false, true); err != nil {
		return ServerConfig{}, err
	}
	if config.MaxConnections < 1 || config.MaxConnections > 128 || config.MaxFileBytes < 1 || config.MaxFileBytes > 1<<40 {
		return ServerConfig{}, errors.New("服务端连接数或文件大小上限无效")
	}
	if len(config.Users) < 1 || len(config.Users) > 128 {
		return ServerConfig{}, errors.New("配置须包含 1 至 128 个用户")
	}
	base := filepath.Dir(path)
	if err := resolvePaths(base, &path, &config.CertFile, &config.KeyFile, &config.CAFile, &config.AuditFile); err != nil {
		return ServerConfig{}, err
	}
	ids := make(map[string]bool)
	fingerprints := make(map[string]bool)
	for index := range config.Users {
		user := &config.Users[index]
		if !identifier.MatchString(user.ID) || !identifier.MatchString(user.Role) || ids[user.ID] {
			return ServerConfig{}, errors.New("用户 ID 或角色名称无效，或用户 ID 重复")
		}
		ids[user.ID] = true
		fingerprint, err := hex.DecodeString(user.Fingerprint)
		if err != nil || len(fingerprint) != sha256.Size {
			return ServerConfig{}, fmt.Errorf("用户 %s 的证书指纹无效", user.ID)
		}
		user.Fingerprint = hex.EncodeToString(fingerprint)
		if fingerprints[user.Fingerprint] {
			return ServerConfig{}, errors.New("两个用户不能共用一个证书身份")
		}
		fingerprints[user.Fingerprint] = true
		if user.BytesPerSecond < 1 || user.BytesPerSecond > 1<<40 || user.QuotaBytes < 1 || user.QuotaBytes > 1<<50 {
			return ServerConfig{}, fmt.Errorf("用户 %s 的带宽或存储配额无效", user.ID)
		}
		if err := resolvePaths(base, &user.Root); err != nil {
			return ServerConfig{}, err
		}
		for _, other := range config.Users[:index] {
			if inside(other.Root, user.Root) || inside(user.Root, other.Root) {
				return ServerConfig{}, errors.New("用户文件目录不能重叠")
			}
		}
		for _, protected := range []string{path, config.CertFile, config.KeyFile, config.CAFile, config.AuditFile} {
			if inside(user.Root, protected) {
				return ServerConfig{}, errors.New("用户文件目录不能包含服务端配置、密钥或审计文件")
			}
		}
	}
	return config, nil
}

func LoadClient(path string) (ClientConfig, error) {
	var config ClientConfig
	path, err := readConfig(path, &config)
	if err != nil {
		return ClientConfig{}, err
	}
	host, err := splitAddress(config.Address, false)
	if err != nil || !validHostName(host) {
		return ClientConfig{}, errors.New("服务端地址无效")
	}
	if !validHostName(config.ServerName) {
		return ClientConfig{}, errors.New("服务端证书校验名称无效")
	}
	if _, err := listenHost(config.UIListen, true, true); err != nil {
		return ClientConfig{}, err
	}
	if err := resolvePaths(filepath.Dir(path), &path, &config.CertFile, &config.KeyFile, &config.CAFile, &config.Downloads); err != nil {
		return ClientConfig{}, err
	}
	for _, protected := range []string{path, config.CertFile, config.KeyFile, config.CAFile} {
		if inside(config.Downloads, protected) {
			return ClientConfig{}, errors.New("下载目录不能包含客户端配置或证书凭据")
		}
	}
	return config, nil
}

func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func tlsCredentials(certFile, keyFile, caFile string) (tls.Certificate, *x509.CertPool, error) {
	keypair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("加载身份凭据: %w", err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("读取实验 CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return tls.Certificate{}, nil, errors.New("实验 CA 文件未包含有效证书")
	}
	return keypair, roots, nil
}

func (config ServerConfig) TLS() (*tls.Config, error) {
	keypair, ca, err := tlsCredentials(config.CertFile, config.KeyFile, config.CAFile)
	if err != nil {
		return nil, err
	}
	registered := make(map[string]bool, len(config.Users))
	for _, user := range config.Users {
		registered[user.Fingerprint] = true
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{keypair},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              ca,
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || !registered[Fingerprint(state.PeerCertificates[0])] {
				return errors.New("客户端证书未注册")
			}
			return nil
		},
	}, nil
}

func (config ClientConfig) TLS() (*tls.Config, error) {
	keypair, ca, err := tlsCredentials(config.CertFile, config.KeyFile, config.CAFile)
	if err != nil {
		return nil, err
	}
	if !validHostName(config.ServerName) {
		return nil, errors.New("服务端证书校验名称无效")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{keypair},
		RootCAs:      ca,
		ServerName:   config.ServerName,
	}, nil
}
