package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const DefaultListen = "127.0.0.1:43951"

func certificateTemplate(name string, now time.Time) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"EX1B local experiment"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 1, 0),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}, nil
}

func saveIdentity(directory, name string, template, authority *x509.Certificate, signingKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, authority, &key.PublicKey, signingKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	base := filepath.Join(directory, "credentials", name)
	if err := os.WriteFile(base+"-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(base+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0o644); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(cert)
}

func saveConfig(directory, name string, config any) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, name+".json"), append(data, '\n'), 0o600)
}

func includeServerName(cert *x509.Certificate, name string) {
	if ip := net.ParseIP(name); ip != nil {
		for _, existing := range cert.IPAddresses {
			if existing.Equal(ip) {
				return
			}
		}
		cert.IPAddresses = append(cert.IPAddresses, ip)
		return
	}
	for _, existing := range cert.DNSNames {
		if existing == name {
			return
		}
	}
	cert.DNSNames = append(cert.DNSNames, name)
}

// InitDemo creates a fresh demo configuration and uniquely generated TLS keys.
// The target must not exist. The demo CA signing key is never written to disk.
func InitDemo(dir, serverAddress, serverName string) error {
	if serverAddress == "" {
		serverAddress = DefaultListen
	}
	host, err := listenHost(serverAddress, false, false)
	if err != nil {
		return err
	}
	if serverName == "" {
		serverName = host
	}
	if !validHostName(serverName) {
		return errors.New("证书名称必须是明确的域名或 IP 地址")
	}
	if dir == "" {
		return errors.New("需要指定配置目录")
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("初始化目录必须尚未存在: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(dir)
		}
	}()
	ids := []string{"alice", "vip"}
	paths := []string{"credentials", "logs"}
	for _, id := range ids {
		paths = append(paths, filepath.Join("data", id), filepath.Join("downloads", id))
	}
	for _, name := range paths {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			return err
		}
	}
	now := time.Now()
	authority, err := certificateTemplate("EX1B demo CA", now)
	if err != nil {
		return err
	}
	authority.IsCA = true
	authority.MaxPathLenZero = true
	authority.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caDER, err := x509.CreateCertificate(rand.Reader, authority, authority, &signingKey.PublicKey, signingKey)
	if err != nil {
		return err
	}
	const caPath = "credentials/ca.pem"
	if err := os.WriteFile(filepath.Join(dir, caPath), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		return err
	}
	authority, err = x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	server, err := certificateTemplate(serverName, now)
	if err != nil {
		return err
	}
	server.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	for _, name := range []string{"localhost", "127.0.0.1", "::1", host, serverName} {
		includeServerName(server, name)
	}
	if _, err := saveIdentity(dir, "server", server, authority, signingKey); err != nil {
		return err
	}
	config := ServerConfig{
		Listen: serverAddress, CertFile: "credentials/server.pem", KeyFile: "credentials/server-key.pem", CAFile: caPath,
		MaxConnections: 24, MaxFileBytes: 64 << 20, AuditFile: "logs/audit.jsonl",
	}
	for index, id := range ids {
		template, err := certificateTemplate(id, now)
		if err != nil {
			return err
		}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		cert, err := saveIdentity(dir, id, template, authority, signingKey)
		if err != nil {
			return err
		}
		role, bandwidth := "normal", int64(256<<10)
		if id == "vip" {
			role, bandwidth = "vip", 1<<20
		}
		config.Users = append(config.Users, User{
			ID: id, Role: role, Root: "data/" + id, BytesPerSecond: bandwidth,
			QuotaBytes: 128 << 20, Fingerprint: Fingerprint(cert),
		})
		client := ClientConfig{
			Address: serverAddress, ServerName: serverName, CertFile: "credentials/" + id + ".pem",
			KeyFile: "credentials/" + id + "-key.pem", CAFile: caPath,
			UIListen: fmt.Sprintf("127.0.0.1:%d", 43952+index), Downloads: "downloads/" + id,
		}
		if err := saveConfig(dir, id, client); err != nil {
			return err
		}
	}
	if err := saveConfig(dir, "server", config); err != nil {
		return err
	}
	complete = true
	return nil
}
