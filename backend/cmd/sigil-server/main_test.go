package main

import "testing"

func TestNormalizeDNSName(t *testing.T) {
	normalized, err := normalizeDNSName("  Station.Example.Test.  ")
	if err != nil {
		t.Fatal(err)
	}
	if normalized != "station.example.test" {
		t.Fatalf("normalized DNS name = %q", normalized)
	}
	for _, invalid := range []string{
		"",
		"127.0.0.1",
		"-bad.example.test",
		"bad-.example.test",
		"bad_name.example.test",
		"bad..example.test",
	} {
		if _, err := normalizeDNSName(invalid); err == nil {
			t.Errorf("invalid DNS name %q was accepted", invalid)
		}
	}
}
