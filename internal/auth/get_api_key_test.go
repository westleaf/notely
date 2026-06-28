package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       map[string]string
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key",
			headers: map[string]string{
				"Authorization": "ApiKey valid_api_key",
			},
			expectedKey:   "valid_api_key",
			expectedError: nil,
		},
		{
			name: "No Authorization Header",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			expectedKey:   "",
			expectedError: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: map[string]string{
				"Authorization": "Bearer invalid_token",
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			for key, value := range tt.headers {
				headers.Set(key, value)
			}

			apiKey, err := auth.GetAPIKey(headers)

			if apiKey != tt.expectedKey {
				t.Errorf("expected API key %s, got %s", tt.expectedKey, apiKey)
			}
			if (err != nil && tt.expectedError == nil) || (err == nil && tt.expectedError != nil) || (err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}
