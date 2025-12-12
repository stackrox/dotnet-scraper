package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNVDRateLimitInterval(t *testing.T) {
	t.Run("With NVD API key", func(t *testing.T) {
		t.Setenv("NVD_API_KEY", "SOMETHING")

		interval := nvdRateLimitInterval()

		// 50 per 30 seconds
		assert.Equal(t, 30*time.Second, (interval * 50))
		assert.Equal(t, 600*time.Millisecond, interval)
	})

	t.Run("Without NVD API key", func(t *testing.T) {
		interval := nvdRateLimitInterval()

		// 5 per 30 seconds
		assert.Equal(t, 30*time.Second, (interval * 5))
		assert.Equal(t, 6*time.Second, interval)
	})
}
