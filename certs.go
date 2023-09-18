package goproxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/hashicorp/go-rootcerts"
)

var GoproxyCaConfig *GoproxyConfig

func rootCAs(c *rootcerts.Config) *tls.Config {
	t := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		Renegotiation:      tls.RenegotiateFreelyAsClient,
	}
	err := rootcerts.ConfigureTLS(t, c)
	if err != nil {
		fmt.Println("[Warning] Error loading root certs", err)
	}
	return t
}

func LoadDefaultConfig() error {
	config, err := LoadCAConfig(CA_CERT, CA_KEY)
	if err != nil {
		return fmt.Errorf("Error parsing builtin CA: %s", err.Error())
	}
	GoproxyCaConfig = config
	return nil
}

// Load a CAConfig bundle from by arrays.  You can then load them into
// the proxy with `proxy.SetMITMCertConfig`
func LoadCAConfig(caCert, caKey []byte) (*GoproxyConfig, error) {
	ca, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		fmt.Println("tls.X509KeyPair failed:",err)
		return nil, err
	}
	priv := ca.PrivateKey

	ca509, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		fmt.Println("tls.ParseCertificate failed:",err)
		return nil, err
	}
	config, err := NewConfig(ca509, priv)
	return config, err
}

var tlsClientSkipVerify = rootCAs(nil)

var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIID0TCCArmgAwIBAgIJAImi7ScXIjQkMA0GCSqGSIb3DQEBCwUAMH8xCzAJBgNV
BAYTAkdCMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxvbmRvbjETMBEGA1UE
CgwKQmxhY2tIb3N0czELMAkGA1UECwwCSVQxDzANBgNVBAMMBkdob3N0czEbMBkG
CSqGSIb3DQEJARYMbm9uQG5vbmUuY29tMB4XDTIzMDkxODIxMzg0MVoXDTI2MDMx
ODIxMzg0MVowfzELMAkGA1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UE
BwwGTG9uZG9uMRMwEQYDVQQKDApCbGFja0hvc3RzMQswCQYDVQQLDAJJVDEPMA0G
A1UEAwwGR2hvc3RzMRswGQYJKoZIhvcNAQkBFgxub25Abm9uZS5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHSFVk/qR6HoTezPRd9UzidXeGOBBU
LOj7z+Ki3zU1DGZVG2mYKh8ZpxGbJ4NPp/LjPWrQCgxTgm6vbhURIs+nluzFaKYT
Xkw0UHLL/hKbo6O0dO2/j4q4xeBu4LnNz28UsopH3H73F+6DZOlrDbvVr88r+QkS
ydx9I4tyyOOyXfqc06AfG8B3YjGLGuB1XVQOTrnzlcCKDRhXfm/a+JIIrgku/seW
zYz6KNEZJ8fJ6mbJrwuV36AEzdF+9zNlwYfRFjXBnfvPFbkO8S2h6eiyPuG3Bvcl
9rRZALLCIJd9rIdnZ5sn2ptVnpYa7EvU0fGgnyCHfrT3HDTPZFzDnxCBAgMBAAGj
UDBOMB0GA1UdDgQWBBS6KRqJpcOxJvOGiFVxngeyelwaCDAfBgNVHSMEGDAWgBS6
KRqJpcOxJvOGiFVxngeyelwaCDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQC2n2dxFMsSIS4cv7i+XHLAqoZYdqoLbdRf60Hsksh5hMqqnqlQeIUCkfIe
do8thmDRMLjvf4CwTa17JL8h/wS9krl5E94rP7HX5/5AdQrsiY6JYrhf4UG3eAfA
62Y8C0/D5KCE6Rb20JBcmy7ldXAeoBxusBihySSESimdUKoDvL3Y6VAtert/iClc
xca45gSb6JDinRhD5bnbMQ2N8mSvz9ANL1GGXDH/FPJwi+pOS/KygpSV3mL+fp+I
qxkmbzx1N/FGW0gjhGUcHFK+S8KspWVmTLuKvIAxIuSMsDbFqjME6VSWdv0TaklW
tuUasOnwOrPG0YSw1UoHk+8+2kjg
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAx0hVZP6keh6E3sz0XfVM4nV3hjgQVCzo+8/iot81NQxmVRtp
mCofGacRmyeDT6fy4z1q0AoMU4Jur24VESLPp5bsxWimE15MNFByy/4Sm6OjtHTt
v4+KuMXgbuC5zc9vFLKKR9x+9xfug2Tpaw271a/PK/kJEsncfSOLcsjjsl36nNOg
HxvAd2IxixrgdV1UDk6585XAig0YV35v2viSCK4JLv7Hls2M+ijRGSfHyepmya8L
ld+gBM3RfvczZcGH0RY1wZ37zxW5DvEtoenosj7htwb3Jfa0WQCywiCXfayHZ2eb
J9qbVZ6WGuxL1NHxoJ8gh3609xw0z2Rcw58QgQIDAQABAoIBAFZOVmVx/wvAce0I
OIEEvrKJCyW+3BuIg7Ki+tVs898wqpULVTUIcQWsHGzktPLnmsKdk8fbwjDcmVEy
zL7qI6LCM3LfeqWCvmAdw0njlG2BdmGuDlVbNkoFsMh0XSPsRYBiPo8WyIn8/Fg9
ePXbMdE+3et+ZFaVw/8SSM+Cf1J8qh1LoFLWKmFKt2WcBrfcoRPruNjpg7qrjQyW
AMmTsMQDfbTFrfK7dBGzE0ESbjSFobqtoSY5CW3ceosNHL5dHBQzgMMz9ufrNFlF
r9bZ9fwR/dmDPZJKPf3iIWybq502QVufakmav7oS4vlp66SN0CvuLIrGeXAuKnE1
eaLZCX0CgYEA/YPQS/4JswFuCkbT/4AI6oS18DMaIAfe774WAo/5PVQ+RP3tFHXJ
M3xA5Wz7BBGUvJDwsN2b4GJdSXax3idap6AgpY53zvkiWRl9FHe4PIr37lAx9FAt
68PEMLLOcI0CRVqsOb00gt7/rDUWud7QN2sjzOj12gzsrdlZ06Qn9k8CgYEAyTxt
A2st4DAWgut1TI/P8+Hj7nboYM1fivSae1AiWbabo8FXYLSJOfVU5PhBzfLWIt0M
Wz6G6SlBLzjA8BYBQhzr9TYuoBsVgtwir/vYPusN5O4NJcfjEFKiqPH4fMeSz6y9
WPuzJxzThhzPF/opHjE0EYZjqCf/703bCArLqC8CgYEAwaRMl68so3GlJu5hAlk+
9jt2aUnvW6YHcKKGV2C3pVPS2IoI7Ebn746qV1Q+DCaNsNcZMk+jv+oCjZm/VQxE
X6OdLDg9ZXfA98PTWa30qTIRHRReg9o2qU54biY2L5xVrroKsXPHR2ukaVqHyGPc
MWiCCQOsvuh+ZHCP/2v1JlsCgYBomiJITqQQDq8E6oOUgoSjzt1+DQ0JlHd/cVoD
k0nnvEX2vv8+Y1mZaO7x/iGmff3VLXXI0B2sgSdC9otDwQxyYzo7wihGTQ3HccoO
FCj5u5EDWMI4y0g6KdonW2/A3LRxgucBpAQh5pgE9GCpo/1Pll/sZCDVPcWJjLy3
13S5PQKBgH6DQFKydn5ya8CJjFqooBcxwDnmvN+dmxdBICkC2aXHGNToXXhosa6K
r40lmYZI6+03iGPyQxEsPVGiW4GJOavR6vx+SowqCQIXTPdyeowTTnzkKS2b154i
zdecNIQki6f5k6tbMKIVmEBCQIdTxTXwkmaGFvFpPGuoBUzsDfgO
-----END RSA PRIVATE KEY-----`)
