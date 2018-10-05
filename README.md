# certinfo [![GoDoc](https://godoc.org/github.com/carlmjohnson/certinfo?status.svg)](https://godoc.org/github.com/carlmjohnson/certinfo) [![Go Report Card](https://goreportcard.com/badge/github.com/carlmjohnson/certinfo)](https://goreportcard.com/report/github.com/carlmjohnson/certinfo)

Get information about the certificate used at a domain

## Installation

First install [Go](http://golang.org).

If you just want to install the binary to your current directory and don't care about the source code, run

```bash
GOBIN="$(pwd)" GOPATH="$(mktemp -d)" go get github.com/carlmjohnson/certinfo
```

## Screenshots

```bash
$ certinfo --help
Usage of certinfo

    certinfo [options] <host>...

Options:
  -port int
        Port to look for TLS certificates on (default 443)


$ certinfo example.com
2018/10/05 16:13:05 connecting to example.com:443
[
  {
    "Host": "example.com",
    "Port": 443,
    "Certs": [
      {
        "Issuer": "CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US",
        "Subject": "CN=www.example.org,OU=Technology,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US",
        "NotBefore": "2015-11-03T00:00:00Z",
        "NotAfter": "2018-11-28T12:00:00Z",
        "DNSNames": [
          "www.example.org",
          "example.com",
          "example.edu",
          "example.net",
          "example.org",
          "www.example.com",
          "www.example.edu",
          "www.example.net"
        ]
      }
    ]
  }
]
```
