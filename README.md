# TLS SNI router

[![license](https://img.shields.io/github/license/google/tlsrouter.svg?maxAge=2592000)](https://github.com/google/tlsrouter/blob/master/LICENSE) [![Travis](https://img.shields.io/travis/google/tlsrouter.svg?maxAge=2592000)](https://travis-ci.org/google/tlsrouter)  [![api](https://img.shields.io/badge/api-unstable-red.svg)](https://godoc.org/go.universe.tf/tlsrouter)

TLSRouter is a TLS proxy that routes connections to backends based on the TLS SNI (Server Name Indication) of the TLS handshake. It carries no encryption keys and cannot decode the traffic that it proxies.

This is not an official Google project.

## Installation

Install TLSRouter via `go get`:

```shell
go get go.universe.tf/tlsrouter
```

## Usage

TLSRouter requires a configuration file that tells it what backend to
use for a given hostname. The config file looks like:

```
# Basic hostname -> backend mapping
go.universe.tf localhost:1234

# DNS wildcards are understoor as well.
*.go.universe.tf 1.2.3.4:8080

# DNS wildcards can go anywhere in name.
google.* 10.20.30.40:443

# RE2 regexes are also available
/(alpha|beta|gamma)\.mon(itoring)?\.dave\.tf/ 100.200.100.200:443
```

TLSRouter takes 2 commandline arguments: the listen address (":443" by default), and
configuration to use.

```shell
tlsrouter -listen 1.2.3.4:443 -conf tlsrouter.conf
```
