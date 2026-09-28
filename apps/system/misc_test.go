package main

import "testing"

func TestLeftoverRoutesAreClaimed(t *testing.T) {
	for _, pattern := range []string{
		"POST /api/v1/github/token",
	} {
		if _, ok := routeHandlers[pattern]; !ok {
			t.Errorf("%s is not registered", pattern)
		}
	}
}
