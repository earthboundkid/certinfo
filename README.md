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
  -expires duration
        error if cert expiration time is less than this; use 0 to disable (default 168h0m0s)
  -output mode
        output mode: text, json, or none (default text)
  -port int
        Port to look for TLS certificates on (default 443)
  -timeout duration
        time out on TCP dialing (default 5s)
  -verbose
        log connections

$ certinfo example.com
Host: example.com:443
Certs:
    Issuer: DigiCert SHA2 High Assurance Server CA
    Subject: www.example.org
    Not Before: Nov 3, 2015 12:00 AM
    Not After: Nov 28, 2018 12:00 PM
    DNS names: www.example.org example.com example.edu example.net example.org www.example.com www.example.edu www.example.net

$ certinfo -output json -verbose example.com
2018/11/04 19:19:15 connecting to example.com:443
[
  {
    "Host": "example.com",
    "Port": 443,
    "Certs": [
      {
        // snip many fields!
      }
    ]
  }
]

$ certinfo -output none -expires 24h example.com

$ certinfo -output none -expires 480h example.com
Runtime error: cert for www.example.org expires too soon: 2018-11-28T12:00:00Z less than 480h0m0s away

```
