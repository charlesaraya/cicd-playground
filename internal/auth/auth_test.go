package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	var gotHeader http.Header
	correctKey := "CorrectKey"
	//incorrectKey := "Incorrect Key"
	t.Run("fail missing authorization header", func(t *testing.T) {
		gotHeader = http.Header{}
		_, err := GetAPIKey(gotHeader)
		if !errors.Is(err, ErrNoAuthHeaderIncluded) {
			t.Errorf("expected %s, got %s", ErrNoAuthHeaderIncluded.Error(), err.Error())
		}
	})
	t.Run("pass correct Authorization header", func(t *testing.T) {
		gotHeader.Set("Authorization", "ApiKey "+correctKey)
		gotKey, err := GetAPIKey(gotHeader)
		if err != nil && correctKey != gotKey {
			t.Errorf("used token %s, got %s", correctKey, gotKey)
		}
	})
	t.Run("fail malformed authorization header with no ApiKey", func(t *testing.T) {
		gotHeader.Set("Authorization", "SomethingElse "+correctKey)
		_, err := GetAPIKey(gotHeader)
		if !errors.Is(err, ErrMalformedAuthHeader) {
			t.Errorf("expected %s, got %s", ErrMalformedAuthHeader.Error(), err.Error())
		}
	})
	t.Run("fail malformed authorization header with no Key", func(t *testing.T) {
		gotHeader.Set("Authorization", "ApiKey")
		_, err := GetAPIKey(gotHeader)
		if !errors.Is(err, ErrMalformedAuthHeader) {
			t.Errorf("expected %s, got %s", ErrMalformedAuthHeader.Error(), err.Error())
		}
	})
}
