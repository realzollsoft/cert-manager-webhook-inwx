package util_test

import (
	"testing"

	"github.com/realzollsoft/cert-manager-webhook-inwx/internal/util"
)

func TestGatherConfig(t *testing.T) {
	tests := []struct {
		name       string
		fqdnNaming bool
		inZone     string
		fqdn       string
		expected   string
	}{
		{
			name:       "fqdn naming enabled",
			fqdnNaming: true,
			inZone:     "example.com.",
			fqdn:       "_acme-challenge.example.com.",
			expected:   "_acme-challenge.example.com",
		},
		{
			name:       "fqdn naming disabled",
			fqdnNaming: false,
			inZone:     "example.com.",
			fqdn:       "_acme-challenge.example.com.",
			expected:   "_acme-challenge",
		},
		{
			name:       "fqdn naming fallback",
			fqdnNaming: false,
			inZone:     "_acme-challenge.example.com.",
			fqdn:       "_acme-challenge.example.com.",
			expected:   "_acme-challenge.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := util.GatherName(tt.fqdnNaming, tt.fqdn, tt.inZone)
			if res != tt.expected {
				t.Errorf("expected res: %v to be equal to %v", res, tt.expected)
			}
		})
	}
}

func TestRemoveDotSuffixes(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		expected string
	}{
		{
			name:     "common case",
			in:       "_acme-challenge.example.com.",
			expected: "_acme-challenge.example.com",
		},
		{
			name:     "multiple dots at end",
			in:       "_acme-challenge.example.com...",
			expected: "_acme-challenge.example.com",
		},
		{
			name:     "no dots at end",
			in:       "_acme-challenge.example.com",
			expected: "_acme-challenge.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := util.RemoveDotSuffixes(tt.in)
			if res != tt.expected {
				t.Errorf("expected res: %v to be equal to %v", res, tt.expected)
			}
		})
	}
}
