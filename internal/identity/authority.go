package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Authority issues identities for the Web gateway and its storage transport.
// Its generated signing material stays in the private runtime data directory.
type Authority struct {
	dir         string
	Certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

func OpenAuthority(dir string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "authority.pem")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		root, makeErr := certificateTemplate("EX1B Web local CA", time.Now())
		if makeErr != nil {
			return nil, makeErr
		}
		root.IsCA = true
		root.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		root.MaxPathLenZero = true
		root.NotAfter = root.NotBefore.AddDate(2, 0, 0)
		key, makeErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if makeErr != nil {
			return nil, makeErr
		}
		cert, makeErr := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
		if makeErr != nil {
			return nil, makeErr
		}
		data, makeErr = encodeKeypair(cert, key)
		if makeErr != nil {
			return nil, makeErr
		}
		err = writeIdentity(path, data, 0600)
	}
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(data, data)
	if err != nil || pair.Leaf == nil || !pair.Leaf.IsCA {
		return nil, errors.New("本地证书签发凭据无效")
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("签发密钥类型无效")
	}
	out := &Authority{dir: dir, Certificate: pair.Leaf, key: key}
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Leaf.Raw})
	if err := writeIdentity(out.CAFile(), public, 0644); err != nil {
		return nil, err
	}
	return out, nil
}

func (a *Authority) CAFile() string { return filepath.Join(a.dir, "ca.pem") }

func (a *Authority) Server(name string, hosts ...string) (string, *x509.Certificate, error) {
	return a.leaf(name, x509.ExtKeyUsageServerAuth, hosts)
}

func (a *Authority) Client(id string) (string, *x509.Certificate, error) {
	if !identifier.MatchString(id) {
		return "", nil, errors.New("账号名不能用于证书签发")
	}
	return a.leaf("user-"+id, x509.ExtKeyUsageClientAuth, nil)
}

func (a *Authority) leaf(name string, usage x509.ExtKeyUsage, hosts []string) (string, *x509.Certificate, error) {
	if !identifier.MatchString(strings.TrimPrefix(name, "user-")) {
		return "", nil, errors.New("证书角色名无效")
	}
	path := filepath.Join(a.dir, name+".pem")
	pair, err := tls.LoadX509KeyPair(path, path)
	if err == nil {
		leaf := pair.Leaf
		if leaf == nil || leaf.Subject.CommonName != name || leaf.CheckSignatureFrom(a.Certificate) != nil || time.Now().After(leaf.NotAfter) {
			return "", nil, errors.New("证书失效或签发链不匹配")
		}
		for _, host := range hosts {
			if leaf.VerifyHostname(host) != nil {
				return "", nil, fmt.Errorf("现有 Web 证书未包含 %s，请使用原 Web 地址或新的演示数据目录", host)
			}
		}
		return path, leaf, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", nil, err
	}
	template, err := certificateTemplate(name, time.Now())
	if err != nil {
		return "", nil, err
	}
	template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
	for _, host := range hosts {
		if !validHostName(host) {
			return "", nil, errors.New("证书主机名无效")
		}
		includeServerName(template, host)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, a.Certificate, &key.PublicKey, a.key)
	if err != nil {
		return "", nil, err
	}
	data, err := encodeKeypair(raw, key)
	if err != nil {
		return "", nil, err
	}
	if err := writeIdentity(path, data, 0600); err != nil {
		return "", nil, err
	}
	cert, err := x509.ParseCertificate(raw)
	return path, cert, err
}

func encodeKeypair(cert []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}),
	}, nil), nil
}

func writeIdentity(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".new-cert-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
