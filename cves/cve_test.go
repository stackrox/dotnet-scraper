package cves

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/stackrox/dotnet-scraper/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseYAMLs(t *testing.T) {
	files, err := os.ReadDir(".")
	require.NoError(t, err)

	for _, f := range files {
		if filepath.Ext(f.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(f.Name())
		assert.NoError(t, err)

		var cd types.CVEDefinition
		assert.NoError(t, yaml.Unmarshal(data, &cd))
		assert.NotEqual(t, len(cd.AffectedPackages), 0)
	}
}
