package parser

import (
	"github.com/Tencent/AI-Infra-Guard/pkg/httpx"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSingleRule(t *testing.T) {
	rule := "body~=\"123123\" && (title == \"title\" || header=\"X-Powered-By: Express\")"
	config := &Config{
		Body:   "1111231232233",
		Header: "",
		Icon:   23333,
	}
	tokens, err := ParseTokens(rule)
	if err != nil {
		t.Fatal(err)
	}
	if err = CheckBalance(tokens); err != nil {
		t.Fatal(err)
	}
	dsl, err := TransFormExp(tokens)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, dsl.Eval(config), true)
}

func TestSingleRuleForParse(t *testing.T) {
	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	assert.NoError(t, err)
	httpOptions := &httpx.HTTPOptions{
		Timeout:          time.Duration(30) * time.Second,
		RetryMax:         3,
		FollowRedirects:  false,
		HTTPProxy:        "",
		Unsafe:           false,
		DefaultUserAgent: httpx.GetRandomUserAgent(),
		Dialer:           dialer,
	}
	hp, err := httpx.NewHttpx(httpOptions)
	assert.NoError(t, err)
	resp, err := hp.Get("https://security.tencent.com/index.php", nil)
	config := &Config{
		Body:   resp.DataStr,
		Header: resp.GetHeaderRaw(),
		Icon:   3444,
	}
	rule := "header=\"nginx\" || header=\"X-Powered-By: Express\""
	fp, err := transfromRule(rule)
	assert.NoError(t, err)
	x := fp.Eval(config)
	t.Log(x)
}

func TestParseAdvisorTokens(t *testing.T) {
	tokens, err := ParseAdvisorTokens(`version > "1.2.3" && version < "2.3.dev"`)
	assert.NoError(t, err)
	err = CheckBalance(tokens)
	assert.NoError(t, err)
	dsl, err := TransFormExp(tokens)
	assert.NoError(t, err)
	config := &AdvisoryConfig{
		Version: "1.3",
	}
	b := dsl.AdvisoryEval(config)
	t.Log(b)
	//assert.Equal(t, dsl.AdvisoryEval(config), true)
}

func TestParseAdvisorLatestTokens(t *testing.T) {
	tokens, err := ParseAdvisorTokens(`version > "0" && version < "latest"`)
	assert.NoError(t, err)
	err = CheckBalance(tokens)
	assert.NoError(t, err)
	dsl, err := TransFormExp(tokens)
	assert.NoError(t, err)
	config := &AdvisoryConfig{
		Version: "1.3",
	}
	b := dsl.AdvisoryEval(config)
	t.Log(b)
	//assert.Equal(t, dsl.AdvisoryEval(config), true)
}

func TestInitFingerPrintFromDataWithVersionRange(t *testing.T) {
	yamlContent := []byte(`info:
  name: testfp
  author: test
  severity: info
http:
  - method: GET
    path: '/'
    matchers:
      - body=""
version:
  - method: GET
    path: '/meta'
    extractor:
      part: body
      group: '1'
      regex: 'version:(\\d+\\.\\d+)'
    version_range: '>=0.8.0'
`)

	fp, err := InitFingerPrintFromData(yamlContent)
	require.NoError(t, err)
	require.Len(t, fp.Version, 1)
	require.Equal(t, ">=0.8.0", fp.Version[0].VersionRange)
	require.Equal(t, "GET", fp.Version[0].Method)
}
