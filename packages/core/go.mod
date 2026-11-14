module github.com/solongate/agent-security/packages/core

go 1.25.0

require (
	github.com/mattn/go-isatty v0.0.24
	github.com/solongate/agent-security/packages/crypto v0.0.0
	github.com/solongate/agent-security/packages/shared v0.0.0
)

require golang.org/x/sys v0.28.0 // indirect

replace github.com/solongate/agent-security/packages/shared => ../shared

replace github.com/solongate/agent-security/packages/crypto => ../crypto