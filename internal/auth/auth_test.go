package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		input          http.Header
		expectedAPIKey string
		expectedErr    error
	}{
		{
			name:           "No Authorization Header",
			input:          http.Header{},
			expectedAPIKey: "",
			expectedErr:    errors.New("no authorization header included"),
		},
		{
			name:           "Invalid Authorization Header Length (Length = 1)",
			input:          http.Header{"Authorization": []string{"ApiKey"}},
			expectedAPIKey: "",
			expectedErr:    errors.New("malformed authorization header"),
		},
		{
			name:           "Invalid Authorization Header Prefix",
			input:          http.Header{"Authorization": []string{"AbcKey key"}},
			expectedAPIKey: "",
			expectedErr:    errors.New("malformed authorization header"),
		},
		{
			name:           "Valid Authorization Header",
			input:          http.Header{"Authorization": []string{"ApiKey key"}},
			expectedAPIKey: "key",
			expectedErr:    nil,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(testCase.input)

			if apiKey != testCase.expectedAPIKey {
				t.Errorf("expected: %s, got: %s", testCase.expectedAPIKey, apiKey)
			}

			expectedErrorReturned := (err == nil && testCase.expectedErr == nil)
			expectedErrorReturned = expectedErrorReturned || (err != nil && testCase.expectedErr != nil && err.Error() == testCase.expectedErr.Error())

			if !expectedErrorReturned {
				t.Errorf("expected: %v, got: %v", testCase.expectedErr, err)
			}
		})
	}
}
