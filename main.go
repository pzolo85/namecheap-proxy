package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/namecheap/go-namecheap-sdk/v2/namecheap"
)

type Update struct {
	IP    string `json:"ip"`
	Fqdn  string `json:"fqdn"`
	Type  string `json:"type"`
	Force bool   `json:"force"`
	TTL   int    `json:"ttl"`
}

type Config struct {
	Key     string `required:"true"`
	Port    string `default:"8443"`
	TlsPath string `default:"./"`
	Debug   bool
	NC      *namecheap.ClientOptions
}

var records = make(map[string]map[string]namecheap.DomainsDNSHostRecord)

var key string
var logger *slog.Logger
var cfg Config
var nc *namecheap.Client

func pullRecords(tld string) (count int, err error) {
	hosts, err := nc.DomainsDNS.GetHosts(tld)
	if err != nil {
		return 0, err
	}

	records[tld] = make(map[string]namecheap.DomainsDNSHostRecord)
	for _, host := range *hosts.DomainDNSGetHostsResult.Hosts {
		records[tld][*host.Name] = namecheap.DomainsDNSHostRecord{
			HostName:   host.Name,
			RecordType: host.Type,
			Address:    host.Address,
			TTL:        host.TTL,
		}
	}
	return len(*hosts.DomainDNSGetHostsResult.Hosts), nil
}

func needsUpdate(mr namecheap.DomainsDNSHostRecord, u Update, ok bool) bool {
	if !ok {
		return true
	}
	if u.Force {
		return true
	}
	if u.IP != *mr.Address || u.TTL != *mr.TTL || u.Type != *mr.RecordType {
		return true
	}
	return false
}

// https://go.dev/src/crypto/tls/generate_cert.go
func createCertAndKey() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	keyUsage := x509.KeyUsageDigitalSignature
	keyUsage |= x509.KeyUsageKeyEncipherment
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"NameCheap Wrapper"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	template.DNSNames = append(template.DNSNames, "localhost")
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certOut, err := os.Create(cfg.TlsPath + "cert.pem")
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}
	if err := certOut.Close(); err != nil {
		return err
	}
	logger.Debug("cert created")

	keyOut, err := os.OpenFile(cfg.TlsPath+"key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}
	if err := keyOut.Close(); err != nil {
		return err
	}
	logger.Debug("key created")
	return nil
}

func loadMiddleware(e *echo.Echo) {
	e.Use(middleware.KeyAuth(func(k string, c echo.Context) (bool, error) {
		if k != key {
			return false, echo.ErrUnauthorized
		}
		return true, nil
	}))
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Method == "GET" {
				return next(c)
			}
			if c.Request().ContentLength == 0 {
				return next(c)
			}
			if strings.HasPrefix(strings.ToLower(c.Request().Header.Get("content-type")), "application/json") {
				return next(c)
			}
			return echo.NewHTTPError(400, "invalid content-type")

		}
	})
}

func makeTLS() {
	f, err := os.Stat(cfg.TlsPath + "key.pem")
	if err != nil {
		if err = createCertAndKey(); err != nil {
			panic(err)
		}
	} else {
		if f.Size() == 0 {
			if err = createCertAndKey(); err != nil {
				panic(err)
			}
		}
	}
}

func updateRecord(c echo.Context) error {
	var u Update
	err := c.Bind(&u)
	if err != nil {
		return echo.NewHTTPError(400, err.Error())
	}
	if u.Fqdn == "" {
		return echo.NewHTTPError(400, "fqdn is missing")
	}
	if u.TTL < 300 {
		u.TTL = 300
	}
	if u.Type == "" {
		u.Type = "A"
	}
	if u.IP == "" {
		u.IP = echo.ExtractIPDirect()(c.Request())
	}
	fqdn := strings.Split(u.Fqdn, ".")
	tld := strings.Join(fqdn[len(fqdn)-2:], ".")
	rec := strings.Join(fqdn[:len(fqdn)-2], ".")
	if rec == "" {
		rec = "@"
	}

	memRec, ok := records[tld]
	if !ok {
		_, err = pullRecords(tld)
		if err != nil {
			return echo.NewHTTPError(400, err.Error())
		}
		memRec = records[tld]
	}

	logger.Info("update request", "up", u)

	mr, ok := memRec[rec]

	if needsUpdate(mr, u, ok) {
		count, _ := pullRecords(tld)
		records[tld][rec] = namecheap.DomainsDNSHostRecord{
			HostName:   namecheap.String(rec),
			RecordType: namecheap.String(u.Type),
			Address:    namecheap.String(u.IP),
			TTL:        namecheap.Int(u.TTL),
		}

		rs := make([]namecheap.DomainsDNSHostRecord, 0, count)
		for _, v := range records[tld] {
			if v.HostName != nil {
				rs = append(rs, v)
			}
		}
		logger.Info("About to send record update", "val", rs)
		resp, err := nc.DomainsDNS.SetHosts(&namecheap.DomainsDNSSetHostsArgs{
			Domain:  namecheap.String(tld),
			Records: &rs,
		})
		if err != nil {
			return echo.NewHTTPError(400, err.Error())
		}
		return c.JSON(200, map[string]bool{"updated": *resp.DomainDNSSetHostsResult.IsSuccess})
	}

	return c.JSON(200, map[string]string{"status": "no update"})
}

func main() {

	err := envconfig.Process("hdns", &cfg)
	if err != nil {
		panic(err)
	}

	var lvl = slog.LevelInfo
	if cfg.Debug {
		lvl = slog.LevelDebug
	}

	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: false, Level: lvl}))
	key = cfg.Key
	cfg.Key = "REDACTED"
	if !strings.HasSuffix(cfg.TlsPath, "/") {
		cfg.TlsPath += "/"
	}

	logger.Debug("config loaded", "cfg", cfg)

	nc = namecheap.NewClient(cfg.NC)

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	loadMiddleware(e)

	e.POST("/update-ip", updateRecord)

	makeTLS()

	logger.Info("starting server")
	err = e.StartTLS(":"+cfg.Port, cfg.TlsPath+"cert.pem", cfg.TlsPath+"key.pem")
	if err != http.ErrServerClosed {
		panic(err)
	}

}
