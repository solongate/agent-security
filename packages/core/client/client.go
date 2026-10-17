// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string { return e.Message }

type Client struct {
	Policies Policies
	Settings Settings
	Stats    StatsClient
	Audit    Audit
}

func New() *Client {
	c := &Client{}
	c.Policies = Policies{c}
	c.Settings = Settings{c}
	c.Stats = StatsClient{c}
	c.Audit = Audit{c}
	return c
}