// Package preload 漏洞指纹判断golang语言写法
package preload

import (
	"github.com/Tencent/AI-Infra-Guard/common/fingerprints/parser"
	"github.com/Tencent/AI-Infra-Guard/internal/gologger"
	"github.com/Tencent/AI-Infra-Guard/pkg/httpx"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/remeh/sizedwaitgroup"
)

// FingerPrintFunc 指纹识别接口
// 实现此接口可以添加自定义的指纹识别逻辑
type FingerPrintFunc interface {
	Match(httpx *httpx.HTTPX, uri string) bool
	GetVersion(httpx *httpx.HTTPX, uri string) (string, error)
	Name() string
}

// CollectedFpReqs 返回所有已注册的指纹识别实现
func CollectedFpReqs() []FingerPrintFunc {
	return []FingerPrintFunc{
		Mlflow{},
	}
}

// FpResult 指纹结构体
type FpResult struct {
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	VersionRange string `json:"version_range,omitempty"`
	Type         string `json:"type,omitempty"`
}

// Runner 指纹识别运行器
// 用于执行指纹识别任务
type Runner struct {
	hp  *httpx.HTTPX
	fps []parser.FingerPrint
}

// New 创建新的Runner实例
func New(hp *httpx.HTTPX, fps parser.FingerPrints) *Runner {
	r := &Runner{hp, fps}
	return r
}

// RunFpReqs 执行指纹识别
// uri: 目标URL
// concurrent: 并发数
// faviconHash: favicon图标的hash值
// 返回识别到的指纹结果列表
func (r *Runner) RunFpReqs(uri string, concurrent int, faviconHash int32) []FpResult {
	wg := sizedwaitgroup.New(concurrent)
	mux := sync.Mutex{}
	ret := make([]FpResult, 0)
	uri = strings.TrimRight(uri, "/")

	indexCache, _ := r.hp.Get(uri+"/", nil)

	for _, fp := range r.fps {
		wg.Add()
		go func(fp parser.FingerPrint) {
			defer wg.Done()
			var resp *httpx.Response
			var err error
			for _, req := range fp.Http {
				if req.Path == "/" && req.Method == "GET" {
					resp = indexCache
				} else {
					if req.Method == "POST" {
						resp, err = r.hp.POST(uri+req.Path, req.Data, nil)
					} else {
						resp, err = r.hp.Get(uri+req.Path, nil)
					}
					if err != nil {
						gologger.WithError(err).Debugln("请求失败")
						continue
					}
				}
				if resp == nil {
					continue
				}
				// 文件指纹
				fpConfig := parser.Config{
					Body:   resp.DataStr,
					Header: resp.GetHeaderRaw(),
					Icon:   faviconHash,
				}
				for _, dsl := range req.GetDsl() {
					if parser.Eval(&fpConfig, dsl) {
						name := fp.Info.Name
						version := ""
						version, versionRange, err := EvalFpVersion(uri, r.hp, fp)
						if err != nil {
							gologger.WithError(err).Errorln("获取版本失败")
						}
						mux.Lock()
						type_, ok := fp.Info.Metadata["type"]
						if !ok {
							type_ = ""
						}
						ret = append(ret, FpResult{
							Name:         name,
							Version:      version,
							VersionRange: versionRange,
							Type:         type_,
						})
						mux.Unlock()
						break
					}
				}
			}
		}(fp)
	}
	for _, fpReq := range CollectedFpReqs() {
		wg.Add()
		go func(fpReq FingerPrintFunc) {
			defer wg.Done()
			if fpReq.Match(r.hp, uri) {
				fpresult := FpResult{
					Name:         fpReq.Name(),
					Version:      "",
					VersionRange: "",
					Type:         "",
				}
				version, err := fpReq.GetVersion(r.hp, uri)
				if err == nil {
					fpresult.Version = version
				}
				mux.Lock()
				ret = append(ret, fpresult)
				mux.Unlock()
			}
		}(fpReq)
	}
	wg.Wait()
	ret = r.Deduplication(ret)
	return ret
}

// Deduplication 对指纹识别结果进行去重
// 如果存在相同名称的指纹，保留版本号不为空的结果
func (r *Runner) Deduplication(results []FpResult) []FpResult {
	bestResults := make(map[string]FpResult)

	for _, result := range results {
		current, ok := bestResults[result.Name]
		if !ok {
			bestResults[result.Name] = result
			continue
		}

		shouldReplace := false
		if result.Version != "" {
			if current.Version == "" || current.Version != result.Version {
				shouldReplace = true
			}
		} else if result.VersionRange != "" {
			if current.Version == "" && (current.VersionRange == "" || current.VersionRange != result.VersionRange) {
				shouldReplace = true
			}
		}

		if shouldReplace {
			bestResults[result.Name] = result
		}
	}

	ret := make([]FpResult, 0, len(bestResults))
	for _, v := range bestResults {
		ret = append(ret, v)
	}
	return ret
}

// GetFps 获取当前Runner中的所有指纹规则
func (r *Runner) GetFps() []parser.FingerPrint {
	return r.fps
}

// EvalFpVersion 获取指定指纹的版本信息
// 通过正则表达式从响应中提取版本号
func EvalFpVersion(uri string, hp *httpx.HTTPX, fp parser.FingerPrint) (string, string, error) {
	var version string
	ranges := make([]string, 0)

	for _, req := range fp.Version {
		targetURL := uri + req.Path
		var resp *httpx.Response
		var err error

		switch strings.ToUpper(req.Method) {
		case "POST":
			resp, err = hp.POST(targetURL, req.Data, nil)
		default:
			resp, err = hp.Get(targetURL, nil)
		}
		if err != nil {
			gologger.WithError(err).Errorln("请求失败")
			continue
		}
		// 文件指纹
		fpConfig := &parser.Config{
			Body:   resp.DataStr,
			Header: resp.GetHeaderRaw(),
			Icon:   0,
		}
		matched := true
		if len(req.GetDsl()) > 0 {
			matched = false
			for _, dsl := range req.GetDsl() {
				if parser.Eval(fpConfig, dsl) {
					matched = true
					break
				}
			}
		}

		if !matched {
			continue
		}

		var extractedRanges []string
		version, extractedRanges = extractVersionAndRanges(req, fpConfig, version)
		ranges = append(ranges, extractedRanges...)
	}

	rangeExpr := ""
	if len(ranges) > 0 {
		rangeExpr = strings.Join(ranges, " && ")
	}
	return version, rangeExpr, nil
}

// extractVersionAndRanges evaluates extractor and version range definitions against a response configuration.
func extractVersionAndRanges(req parser.HttpRule, fpConfig *parser.Config, currentVersion string) (string, []string) {
	version := currentVersion
	ranges := make([]string, 0)

	if req.Extractor.Regex != "" && version == "" {
		compileRegex, err := regexp.Compile("(?i)" + req.Extractor.Regex)
		if err != nil {
			gologger.WithError(err).Errorln("compile regex error", req.Extractor.Regex)
		} else {
			index, err := strconv.Atoi(req.Extractor.Group)
			if err != nil {
				gologger.WithError(err).Errorln("parse part error", req.Extractor.Part)
			} else {
				body := fpConfig.Body
				if strings.EqualFold(req.Extractor.Part, "header") {
					body = fpConfig.Header
				}
				submatches := compileRegex.FindStringSubmatch(body)
				if submatches != nil && len(submatches) > index {
					version = submatches[index]
				}
			}
		}
	}

	rangeExpr := strings.TrimSpace(req.VersionRange)
	if rangeExpr != "" {
		ranges = append(ranges, rangeExpr)
	}

	return version, ranges
}
