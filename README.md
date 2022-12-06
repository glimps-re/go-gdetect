[![Build Status](https://github.com/glimps-re/go-gdetect/workflows/Go/badge.svg?branch=main)](https://github.com/glimps-re/go-gdetect/actions?query=branch%3Amain)
[![Go Report Card](https://goreportcard.com/badge/github.com/glimps-re/go-gdetect)](https://goreportcard.com/report/github.com/glimps-re/go-gdetect)
[![GoDoc](https://pkg.go.dev/badge/github.com/glimps-re/go-gdetect?status.svg)](https://pkg.go.dev/github.com/glimps-re/go-gdetect?tab=doc)
[![Release](https://img.shields.io/github/release/glimps-re/go-gdetect.svg?style=flat-square)](https://github.com/glimps-re/go-gdetect/releases)

# go-gdetect - library & client

A Go Client and a library for Glimps Malware detect API.

go-gdetect is a solution from GLIMPS *Inc.* for a better detection of malware. Contact us at contact@glimps.re for more information !  

## Description

go-gdetect aims to simplify use of *Glimps Detect*, a malware detectio solution from GLIMPS *Inc.*.

This tool can be used by two ways:

* As *shell* CLI: `./go-gdetect /path/to/my/binary`
* As go library (see below).


## Usage

### As shell *CLI* tools

Before launch the tool, you can set the path to your GDetect URL and your authentication token into environment variables with:

`export API_URL=https://my.gdetect.service.tld` for the URL;  
`export API_TOKEN=abcdef01-23456789-abcdef01-23456789-abcdef01` for the token.

You can use *go-gdetect* in your shell like this:

```bash
$ go build
$ ./go-gdetect --help
go-gdetect - interact with GLIMPS malware detect API

Usage:
  go-gdetect [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  get         Get a file by its uuid
  help        Help about any command
  search      Search a previous analysis
  submit      Submit a file to gdetect api
  waitfor     Submit a file to gdetect api and wait for results

Flags:
  -h, --help           help for go-gdetect
      --insecure       bypass HTTPS check
      --token string   token to API
      --url string     url to API

Use "go-gdetect [command] --help" for more information about a command.
```

### As a go library

You can perform API call using `Client` from `github.com/glimps-re/go-gdetect/pkg/gdetect`.

```bash
go get github.com/glimps-re/go-gdetect
```

```go
package main

import (
 "context"
 "fmt"
 "github.com/glimps-re/go-gdetect/pkg/gdetect"
)

func main() {
 client, err := gdetect.NewClient("https://my.gdetect.service.tld", "abcdef01-23456789-abcdef01-23456789-abcdef01", false)
 if err != nil {
  return
 }

 result, err := client.GetResultByUUID(context.Background(), "1234")
 if err != nil {
  return
 }
 fmt.Print(result.SHA256)
}

```

## Support

If you have any questions, open an *issue* on Github.

## Authors

***GLIMPS dev core team***

## License

This project is under **MIT License**.

## Project status

This project is in *Beta* development status. Feel free to participate !
