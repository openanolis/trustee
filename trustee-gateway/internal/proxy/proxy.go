package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openanolis/trustee/gateway/internal/config"
	"github.com/sirupsen/logrus"
)

// ServiceType represents the type of service being proxied
type ServiceType string

const (
	// KBSService represents the KBS service
	KBSService ServiceType = "kbs"
)

// Proxy handles the forwarding of requests to backend services
type Proxy struct {
	kbsURL *url.URL
}

// NewProxy creates a new proxy instance
func NewProxy(cfg *config.Config) (*Proxy, error) {
	kbsURL, err := url.Parse(cfg.KBS.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid KBS URL: %w", err)
	}

	return &Proxy{
		kbsURL: kbsURL,
	}, nil
}

// ForwardToKBS forwards a request to the KBS service
func (p *Proxy) ForwardToKBS(c *gin.Context) (*http.Response, error) {
	return p.forwardRequest(c, KBSService)
}

// RequestBodyBuffer is a buffer that records the request body while forwarding it
type RequestBodyBuffer struct {
	*bytes.Buffer
	io.ReadCloser
}

// Read reads from the buffer and the underlying reader
func (r *RequestBodyBuffer) Read(p []byte) (n int, err error) {
	return r.ReadCloser.Read(p)
}

// Close closes the underlying reader
func (r *RequestBodyBuffer) Close() error {
	return r.ReadCloser.Close()
}

// ResponseBodyBuffer is a buffer that records the response body while forwarding it
type ResponseBodyBuffer struct {
	*bytes.Buffer
	io.ReadCloser
}

// Read reads from the underlying reader and writes to the buffer
func (r *ResponseBodyBuffer) Read(p []byte) (n int, err error) {
	n, err = r.ReadCloser.Read(p)
	if n > 0 {
		r.Buffer.Write(p[:n])
	}
	return n, err
}

// Close closes the underlying reader
func (r *ResponseBodyBuffer) Close() error {
	return r.ReadCloser.Close()
}

// forwardRequest forwards a request to a backend service
func (p *Proxy) forwardRequest(c *gin.Context, serviceType ServiceType) (*http.Response, error) {
	var targetURL *url.URL
	switch serviceType {
	case KBSService:
		targetURL = p.kbsURL
	default:
		return nil, fmt.Errorf("unknown service type: %s", serviceType)
	}

	// Create a buffer to store the request body
	requestBodyBuf := new(bytes.Buffer)

	// Create a new request to the target URL
	targetPath := c.Request.URL.Path

	// For KBS, we need to strip the prefix if necessary
	if serviceType == KBSService && !strings.HasPrefix(targetPath, "/kbs/v0") {
		targetPath = "/kbs/v0" + strings.TrimPrefix(targetPath, "/api/kbs/v0")
	}

	targetQuery := c.Request.URL.RawQuery
	targetURL = targetURL.JoinPath(targetPath)

	// If there's a query string, add it to the target URL
	if targetQuery != "" {
		targetURL.RawQuery = targetQuery
	}

	// Copy the request body if it exists
	var targetReq *http.Request
	var err error

	if c.Request.Body != nil {
		// Read and store the request body
		reqBody, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}

		// Store the request body for later use
		requestBodyBuf.Write(reqBody)

		// Create a new request with the same body
		targetReq, err = http.NewRequest(c.Request.Method, targetURL.String(), bytes.NewReader(reqBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create target request: %w", err)
		}
	} else {
		targetReq, err = http.NewRequest(c.Request.Method, targetURL.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create target request: %w", err)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create target request: %w", err)
	}

	// Copy all headers from the original request
	for k, vv := range c.Request.Header {
		for _, v := range vv {
			targetReq.Header.Add(k, v)
		}
	}

	// Copy cookies
	for _, cookie := range c.Request.Cookies() {
		targetReq.AddCookie(cookie)
	}

	// Set X-Forwarded headers
	targetReq.Header.Set("X-Forwarded-For", c.ClientIP())
	targetReq.Header.Set("X-Forwarded-Host", c.Request.Host)
	targetReq.Header.Set("X-Forwarded-Proto", c.Request.URL.Scheme)

	// Create HTTP client with appropriate timeout
	client := &http.Client{
		Timeout: time.Second * 30,
	}

	// Send the request to the target
	resp, err := client.Do(targetReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to target: %w", err)
	}

	// Log the request and response
	if logrus.GetLevel() >= logrus.DebugLevel {
		reqDump, _ := httputil.DumpRequest(targetReq, false)
		logrus.Debugf("Forwarded request to %s:\n%s", targetURL.String(), string(reqDump))

		respDump, _ := httputil.DumpResponse(resp, false)
		logrus.Debugf("Received response from %s:\n%s", targetURL.String(), string(respDump))
	}

	// Create a buffer for the response body
	respBodyBuf := new(bytes.Buffer)

	// Replace the response body with a wrapper that copies to our buffer
	if resp.Body != nil {
		resp.Body = &ResponseBodyBuffer{
			Buffer:     respBodyBuf,
			ReadCloser: resp.Body,
		}
	}

	return resp, nil
}

// CopyHeaders copies headers from a source response to the destination gin context
func CopyHeaders(dst *gin.Context, src *http.Response) {
	for k, vv := range src.Header {
		for _, v := range vv {
			dst.Writer.Header().Add(k, v)
		}
	}
}

// CopyCookies copies cookies from a source response to the destination gin context
func CopyCookies(dst *gin.Context, src *http.Response) {
	for _, cookie := range src.Cookies() {
		http.SetCookie(dst.Writer, cookie)
	}
}
