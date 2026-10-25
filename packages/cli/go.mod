module github.com/solongate/agent-security/packages/cli

go 1.26.0

require (
	github.com/solongate/agent-security/packages/core v0.0.0
	github.com/solongate/agent-security/packages/crypto v0.0.0
	github.com/solongate/agent-security/packages/sandbox v0.0.0-00010101000000-000000000000
	github.com/solongate/agent-security/packages/shared v0.0.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/landlock-lsm/go-landlock v0.10.1 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.77 // indirect
)

replace github.com/solongate/agent-security/packages/core => ../core

replace github.com/solongate/agent-security/packages/shared => ../shared

replace github.com/solongate/agent-security/packages/sandbox => ../sandbox

replace github.com/solongate/agent-security/packages/crypto => ../crypto