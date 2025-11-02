package preload

import (
	"testing"

	"github.com/Tencent/AI-Infra-Guard/common/fingerprints/parser"
	"github.com/stretchr/testify/require"
)

func TestEvalFpVersionWithRange(t *testing.T) {
	fp := parser.FingerPrint{
		Version: []parser.HttpRule{
			{
				Method: "GET",
				Path:   "/",
				Extractor: parser.Extractor{
					Part:  "body",
					Group: "1",
					Regex: `"version":"([0-9.]+)"`,
				},
				Range: []parser.VersionRangeRule{
					{
						Part:  "body",
						Group: "1",
						Regex: `"min":"([0-9.]+)"`,
						Range: `version >= "{{value}}"`,
					},
					{
						Part:  "body",
						Group: "1",
						Regex: `"max":"([0-9.]+)"`,
						Range: `version <= "{{value}}"`,
					},
				},
			},
		},
	}

	config := &parser.Config{Body: `{"version":"2.1.0","min":"2.0.0","max":"2.5.0"}`}
	version, ranges := extractVersionAndRanges(fp.Version[0], config, "")
	require.Equal(t, "2.1.0", version)
	require.Equal(t, []string{`version >= "2.0.0"`, `version <= "2.5.0"`}, ranges)
}

func TestEvalFpVersionRangeWithoutExact(t *testing.T) {
	fp := parser.FingerPrint{
		Version: []parser.HttpRule{
			{
				Method: "GET",
				Path:   "/",
				Range: []parser.VersionRangeRule{
					{
						Part:  "body",
						Group: "1",
						Regex: `"min":"([0-9.]+)"`,
						Range: `version >= "{{value}}"`,
					},
					{
						Part:  "body",
						Group: "1",
						Regex: `"max":"([0-9.]+)"`,
						Range: `version < "{{value}}"`,
					},
				},
			},
		},
	}

	config := &parser.Config{Body: `{"min":"1.0.0","max":"1.9.9"}`}
	version, ranges := extractVersionAndRanges(fp.Version[0], config, "")
	require.Empty(t, version)
	require.Equal(t, []string{`version >= "1.0.0"`, `version < "1.9.9"`}, ranges)
}
