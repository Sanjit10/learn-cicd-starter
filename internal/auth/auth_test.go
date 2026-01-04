package auth_test

import (
	"errors"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)


func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers       map[string][]string
		expectedKey   string
		expectedError error
	}{
		"Intentional failure - expected to fail in CI": {
			headers: map[string][]string{
				"Authorization": {"ApiKey real-key"},
			},
			expectedKey:   "different-key",
			expectedError: nil,
		},
		"No auth header": {
			headers:       map[string][]string{},
			expectedKey:   "",
			expectedError: auth.ErrNoAuthHeaderIncluded,
		},
		"Malformed auth header - no space": {
			headers: map[string][]string{
				"Authorization": {"ApiKey12345"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		"Malformed auth header - wrong prefix": {
			headers: map[string][]string{
				"Authorization": {"Bearer 12345"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		"Valid auth header": {
			headers: map[string][]string{
				"Authorization": {"ApiKey 12345"},
			},
			expectedKey:   "12345",
			expectedError: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := auth.GetAPIKey(tc.headers)
			if key != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, key)
			}
			if (err == nil && tc.expectedError != nil) || (err != nil && tc.expectedError == nil) || (err != nil && tc.expectedError != nil && err.Error() != tc.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}
		})
	}
}
