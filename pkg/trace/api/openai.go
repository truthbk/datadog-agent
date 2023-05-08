package api

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/trace/log"
	"github.com/DataDog/datadog-agent/pkg/trace/metrics"
)

type openaiTransport struct {
	Transport http.RoundTripper
}

func (r *HTTPReceiver) openaiProxyHandler() http.Handler {
	transport := openaiTransport{
		// DEV: I keep getting issues where the client says the remote was closed, but I see we have gotten response data here
		//      I thought maybe it was a timeout issue, so I just copied `r.conf.NewHTTPTransport()` to set higher timeout limits
		//      It didn't seem to work super well, so not likely related at all
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: r.conf.SkipSSLValidation},
			// below field values are from http.DefaultTransport (go1.12)
			Proxy: r.conf.Proxy,
			DialContext: (&net.Dialer{
				Timeout:   120 * time.Second,
				KeepAlive: 120 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       120 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
		},
	}
	limitedLogger := log.NewThrottled(5, 10*time.Second) // limit to 5 messages every 10 seconds
	logger := stdlog.New(limitedLogger, "openai.Proxy: ", 0)

	return &httputil.ReverseProxy{
		ErrorLog:  logger,
		Director:  func(req *http.Request) {},
		Transport: &transport,
	}
}

func (m *openaiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var err error

	var reqHeaders = req.Header.Clone()
	// reqBody, err := readBody(req.Body)
	// if err != nil {
	// 	return nil, err
	// }

	var endpoint string
	switch req.URL.Path {
	case "/v1/completions":
		endpoint = "completions"
	default:
		endpoint = ""
	}

	tags := extractRequestHeaderTags(reqHeaders)
	tags = append(tags, fmt.Sprintf("openai_endpoint:%s", endpoint))

	// TODO: Do we need to process the request data at all?
	// go processRequestData(tags, reqHeaders, reqBody)

	// if reqBody != nil {
	// 	newreq.Body = io.NopCloser(bytes.NewReader(reqBody))
	// }
	req.Host = "api.openai.com"
	req.URL.Host = "api.openai.com"
	req.URL.Scheme = "https"

	// Default to the v1 api if they didn't specify one in `OPENAI_API_BASE`
	if !strings.HasPrefix(req.URL.Path, "/v") {
		req.URL.Path = "/v1" + req.URL.Path
	}

	// Make the request to OpenAI
	startTime := time.Now()
	resp, err := m.Transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	respHeaders := resp.Header.Clone()
	respBody, err := readBody(resp.Body)
	if err != nil {
		return resp, err
	}
	if respBody != nil {
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
	}
	defer processResponseData(tags, respHeaders, respBody, startTime)
	return resp, err
}

// func processRequestData(tags []string, reqHeader http.Header, reqBody []byte) {
// 	var err error

// 	if reqBody == nil {
// 		return
// 	}

// 	var encoding = reqHeader.Get("Content-Encoding")
// 	reqBody, err = decompressBody(encoding, reqBody)
// 	if err != nil {
// 		return
// 	}

// 	var data map[string]interface{}
// 	if json.Unmarshal(reqBody, &data) != nil {
// 		return
// 	}
// }

func processResponseData(tags []string, resHeaders http.Header, respBody []byte, startTime time.Time) {
	var err error

	// Yes... we are counting our response processing in the total duration
	// This is probably ok since we are also measuring the request duration from a proxy
	// and not directly from a client, so the durations are always going to be a bit off
	defer func() {
		metrics.Distribution("openai.request.duration", float64(time.Since(startTime)), tags, 1)
	}()

	// We don't need the body for these
	tags = append(tags, extractResponseHeaderTags(resHeaders)...)
	emitRateLimitMetrics(resHeaders, tags)

	if respBody == nil {
		tags = append(tags, "error:1")
		return
	}

	var encoding = resHeaders.Get("Content-Encoding")
	respBody, err = decompressBody(encoding, respBody)
	if err != nil {
		return
	}

	var data map[string]interface{}
	if json.Unmarshal(respBody, &data) != nil {
		return
	}

	emitUsageMetrics(data, tags)

	if e, ok := data["error"]; ok {
		errorInfo, ok := e.(map[string]interface{})
		if ok {
			if errType, ok := errorInfo["type"]; ok {
				tags = append(tags, fmt.Sprintf("error_type:%s", errType))
			}
		}
		metrics.Count("openai.request.error", 1, tags, 1)
		tags = append(tags, "error:1")
	} else {
		tags = append(tags, "error:1")
	}
}

func decompressBody(encoding string, data []byte) ([]byte, error) {
	if encoding == "gzip" {
		reader := bytes.NewReader(data)
		gzreader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}

		return ioutil.ReadAll(gzreader)
	}
	return data, nil
}

func readBody(body io.ReadCloser) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	return io.ReadAll(body)
}

func extractRequestHeaderTags(headers http.Header) []string {
	tags := []string{}

	authHeader := headers.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			apiKey := parts[1]
			tags = append(tags, fmt.Sprintf("openai.user.api_key:%s", apiKey[len(apiKey)-4:]))
		}
	}

	// Request has the org id
	organizationHeader := headers.Get("Openai-Organization")
	if organizationHeader != "" {
		tags = append(tags, fmt.Sprintf("openai.organization.id:%s", organizationHeader))
	}

	uaHeader := headers.Get("X-Openai-Client-User-Agent")
	if uaHeader != "" {
		var data map[string]interface{}
		if json.Unmarshal([]byte(uaHeader), &data) == nil {
			if lang, ok := data["lang"]; ok {
				tags = append(tags, fmt.Sprintf("lang:%s", lang))
			}
			if lang_version, ok := data["lang_version"]; ok {
				tags = append(tags, fmt.Sprintf("lang_version:%s", lang_version))
			}
			if httplib, ok := data["httplib"]; ok {
				tags = append(tags, fmt.Sprintf("httplib:%s", httplib))
			}
			if publisher, ok := data["publisher"]; ok {
				tags = append(tags, fmt.Sprintf("publisher:%s", publisher))
			}
		}
	}

	return tags
}

func extractResponseHeaderTags(headers http.Header) []string {
	tags := []string{}

	// Response gives back the org name
	organizationHeader := headers.Get("Openai-Organization")
	if organizationHeader != "" {
		tags = append(tags, fmt.Sprintf("openai.organization.name:%s", organizationHeader))
	}

	modelHeader := headers.Get("Openai-Model")
	if modelHeader != "" {
		tags = append(tags, fmt.Sprintf("openai.model:%s", modelHeader))
	}
	versionHeader := headers.Get("Openai-Version")
	if versionHeader != "" {
		tags = append(tags, fmt.Sprintf("version_model:%s", versionHeader))
	}
	return tags
}

func emitRateLimitMetrics(resHeaders http.Header, tags []string) {
	if v := resHeaders.Get("X-Ratelimit-Limit-Requests"); v != "" {
		if f, err := strconv.ParseFloat(v, 32); err == nil {
			metrics.Gauge("openai.ratelimit.requests", f, tags, 1)
		}
	}
	if v := resHeaders.Get("X-Ratelimit-Limit-Tokens"); v != "" {
		if f, err := strconv.ParseFloat(v, 32); err == nil {
			metrics.Gauge("openai.ratelimit.tokens", f, tags, 1)
		}
	}
	if v := resHeaders.Get("X-Ratelimit-Remaining-Requests"); v != "" {
		if f, err := strconv.ParseFloat(v, 32); err == nil {
			metrics.Gauge("openai.ratelimit.remaining.requests", f, tags, 1)
		}
	}
	if v := resHeaders.Get("X-Ratelimit-Remaining-Tokens"); v != "" {
		if f, err := strconv.ParseFloat(v, 32); err == nil {
			metrics.Gauge("openai.ratelimit.remaining.tokens", f, tags, 1)
		}
	}
}

func emitUsageMetrics(data map[string]interface{}, tags []string) {
	usageInterface, ok := data["usage"]
	if !ok {
		return
	}

	usage, ok := usageInterface.(map[string]interface{})
	if !ok {
		return
	}

	if v, ok := usage["prompt_tokens"]; ok {
		if i, ok := v.(float64); ok {
			metrics.Distribution("openai.tokens.prompt", float64(i), tags, 1)
		}
	}

	if v, ok := usage["completion_tokens"]; ok {
		if i, ok := v.(float64); ok {
			metrics.Distribution("openai.tokens.completion", float64(i), tags, 1)
		}
	}

	if v, ok := usage["total_tokens"]; ok {
		if i, ok := v.(float64); ok {
			metrics.Distribution("openai.tokens.total", float64(i), tags, 1)
		}
	}
}
