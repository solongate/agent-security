module github.com/solongate/agent-security/packages/core

go 1.25.0

require (
	github.com/landlock-lsm/go-landlock v0.10.1
	github.com/solongate/agent-security/packages/shared v0.0.0
)

require (
	golang.org/x/sys v0.40.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.77 // indirect
)

replace github.com/solongate/agent-security/packages/shared => ../shared
