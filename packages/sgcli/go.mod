module github.com/solongate/agent-security/packages/sgcli

go 1.25.0

require (
	github.com/solongate/agent-security/packages/sgcore v0.0.0
	github.com/solongate/agent-security/packages/sgshared v0.0.0
)

replace github.com/solongate/agent-security/packages/sgcore => ../sgcore

replace github.com/solongate/agent-security/packages/sgshared => ../sgshared
