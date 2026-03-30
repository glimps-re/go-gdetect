[![Build Status](https://github.com/glimps-re/go-gdetect/workflows/Go/badge.svg?branch=main)](https://github.com/glimps-re/go-gdetect/actions?query=branch%3Amain)
[![Go Report Card](https://goreportcard.com/badge/github.com/glimps-re/go-gdetect)](https://goreportcard.com/report/github.com/glimps-re/go-gdetect)
[![GoDoc](https://pkg.go.dev/badge/github.com/glimps-re/go-gdetect?status.svg)](https://pkg.go.dev/github.com/glimps-re/go-gdetect?tab=doc)
[![Release](https://img.shields.io/github/release/glimps-re/go-gdetect.svg?style=flat-square)](https://github.com/glimps-re/go-gdetect/releases)

# go-gdetect - library & client

A Go Client and a library for Glimps Malware detect API.

go-gdetect is a solution from GLIMPS *Inc.* for a better detection of malware. Contact us at contact@glimps.re for more information !

## Description

go-gdetect aims to simplify the use of *Glimps Detect*, a malware detection solution from GLIMPS *Inc.*.

This tool can be used in two ways:

* As *shell* CLI: `./go-gdetect /path/to/my/binary`
* As go library (see below).


## Usage

### As shell *CLI* tools

Before launching the tool, you can set the path to your GDetect URL and your authentication token into environment variables with:

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
  export      Export result by its uuid
  get         Get a file by its uuid
  help        Help about any command
  search      Search a previous analysis
  status      Get profile status
  submit      Submit a file to gdetect api
  waitfor     Submit a file to gdetect api and wait for results

Flags:
  -h, --help           help for go-gdetect
      --insecure       bypass HTTPS check
      --syndetect      use syndetect API (warning: it's subset of detect capabilities)
      --token string   token to API
      --url string     url to API

Use "go-gdetect [command] --help" for more information about a command.
```

#### Get command

The `get` command retrieves an analysis result by UUID. Use the `--wait` flag to
instruct the server to hold the connection open until the analysis is complete:

```bash
# Immediate retrieval (returns done=false if analysis is still running)
./go-gdetect get <UUID>

# Block for up to 30 seconds waiting for the result
./go-gdetect get <UUID> --wait 30

# Also print Expert View and Token View URLs
./go-gdetect get <UUID> --retrieve-urls
```

The `--wait` value must be between 0 and 59 seconds (inclusive). When `--wait 0` (default),
the server responds immediately. The wait parameter is only used in Detect mode;
in SynDetect mode it has no effect.

#### Export command

The `export` command allows you to export analysis results in various formats:

```bash
# Export to PDF in English
./go-gdetect export <UUID> --format pdf --layout en

# Export full analysis to JSON in French, save to file
./go-gdetect export <UUID> --format json --layout fr --full --output report.json

# Export to MISP format (prints to stdout)
./go-gdetect export <UUID> --format misp --layout en

# Available formats: misp, stix, json, pdf, markdown, csv
# Available layouts: fr, en
```

### As a go library

Requires Go 1.24 or later.

You can perform API calls using `Client` from `github.com/glimps-re/go-gdetect/pkg/gdetect`.

```bash
go get github.com/glimps-re/go-gdetect
```

```go
package main

import (
 "context"
 "fmt"
 "os"
 "github.com/glimps-re/go-gdetect/pkg/gdetect"
)

func main() {
 client, err := gdetect.NewClientFromConfig(gdetect.ClientConfig{
  Endpoint: "https://my.gdetect.service.tld",
  Token:    "abcdef01-23456789-abcdef01-23456789-abcdef01",
 })
 if err != nil {
  return
 }

 // Get analysis result immediately (done may be false if analysis is pending)
 result, err := client.GetResultByUUID(context.Background(), "9618ae7e-e284-405d-8998-ff1e12c7ca27")
 if err != nil {
  return
 }
 fmt.Print(result.SHA256)

 // Block for up to 30 seconds waiting for the analysis to complete
 result, err = client.GetResultByUUIDWithWait(context.Background(), "9618ae7e-e284-405d-8998-ff1e12c7ca27", 30)
 if err != nil {
  return
 }
 fmt.Print(result.Done) // true if analysis completed within 30 s

 // Export analysis to PDF
 exportOptions := gdetect.ExportOptions{
  Format: gdetect.ExportFormatPDF,
  Layout: gdetect.ExportLayoutEN,
  Full:   false,
 }
 data, err := client.ExportResult(context.Background(), "9618ae7e-e284-405d-8998-ff1e12c7ca27", exportOptions)
 if err != nil {
  return
 }
 // Save to file with secure permissions
 os.WriteFile("report.pdf", data, 0o600)
}
```

#### SynDetect mode

The library also supports the SynDetect API variant (a limited subset of Detect). Pass
`Syndetect: true` in `ClientConfig` to activate it. Note that some fields (e.g. `UUID`,
`Threats`) behave differently in SynDetect mode.

#### Testing with the mock package

`github.com/glimps-re/go-gdetect/pkg/gdetect/mock` provides `MockGDetectSubmitter`, a
configurable test double that implements `gdetect.ControllerExtendedGDetectSubmitter`.
Set only the method fields your test needs; unset methods panic with a clear message.

```go
import gdetectmock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"

m := &gdetectmock.MockGDetectSubmitter{
    GetResultByUUIDMock: func(ctx context.Context, uuid string) (gdetect.Result, error) {
        return gdetect.Result{Done: true, SHA256: "abc..."}, nil
    },
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
