# gogdetect - library & client

A Go Client and a library for Glimps Malware detect API.

gogdetect is a solution from GLIMPS *Inc.* for a better detection of malware. Contact us at contact@glimps.re for more information !  

## Description

gogdetect aims to simplify use of *Glimps Detect*, a malware detectio solution from GLIMPS *Inc.*.

This tool can be used by two ways:

* As *shell* CLI: `./gogdetect /path/to/my/binary`
* As go library (see below).

## Installation

TODO

## Usage

### As shell *CLI* tools

Before launch the tool, you can set the path to your GDetect URL and your authentication token into environment variables with:

`export API_URL=https://my.gdetect.service.tld` for the URL;  
`export API_TOKEN=abcdef01-23456789-abcdef01-23456789-abcdef01` for the token.

You can use *gogdetect* in your shell like this:

```txt
❯ ./gogdetect --help
gogdetect - interact with GLIMPS malware detect API

Usage:
  gogdetect [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  get         Get a file by its uuid
  help        Help about any command
  search      Search a previous analysis
  submit      Submit a file to gdetect api
  waitfor     Submit a file to gdetect api and wait for results

Flags:
  -h, --help           help for gogdetect
      --insecure       bypass HTTPS check
      --token string   token to API
      --url string     url to API

Use "gogdetect [command] --help" for more information about a command.
```

### As a go library

You can perform API call using `Client` from `gogdetect/pkg/api`.

```go
package main

import (
 "context"
 "fmt"
 "gogdetect/pkg/api"
)

func main() {
 client, err := api.NewClient("https://my.gdetect.service.tld", "abcdef01-23456789-abcdef01-23456789-abcdef01", false)
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
