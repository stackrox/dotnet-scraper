package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/facebookincubator/nvdtools/cveapi/nvd/schema"
)

// baseURL is NVD's endpoint base URL.
var baseURL *url.URL

func init() {
	var err error
	baseURL, err = url.Parse("https://services.nvd.nist.gov/rest/json/cves/2.0")
	if err != nil {
		panic(err)
	}
}

func validateNVDCVEIsEvaluated(cve string) (bool, error) {
	// Create a copy of the baseURL and update its query parameters.
	q := baseURL.Query()
	q.Set("cveId", cve)
	u := *baseURL
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return false, err
	}

	if apiKey, found := os.LookupEnv("NVD_API_KEY"); found {
		req.Header.Add("apiKey", apiKey)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("NVD API returned status %d (%s): %q", resp.StatusCode, http.StatusText(resp.StatusCode), string(data))
	}

	var result schema.CVEAPIJSON20
	if err := json.Unmarshal(data, &result); err != nil {
		return false, fmt.Errorf("unmarshalling NVD response result: %w", err)
	}
	// CVE not found
	if result.TotalResults == 0 {
		return false, nil
	}
	if result.TotalResults > 1 {
		return false, fmt.Errorf("unexpected number of CVE items (%d) for %s", result.TotalResults, cve)
	}
	fullCVE := result.Vulnerabilities[0].CVE
	if fullCVE.Metrics == nil || (len(fullCVE.Metrics.CvssMetricV2) == 0 &&
		len(fullCVE.Metrics.CvssMetricV30) == 0 &&
		len(fullCVE.Metrics.CvssMetricV31) == 0) {
		return false, nil
	}

	// Verify CVSS data exists.
	for _, metric := range fullCVE.Metrics.CvssMetricV2 {
		if metric.CvssData != nil {
			return true, nil
		}
	}
	for _, metric := range fullCVE.Metrics.CvssMetricV30 {
		if metric.CvssData != nil {
			return true, nil
		}
	}
	for _, metric := range fullCVE.Metrics.CvssMetricV31 {
		if metric.CvssData != nil {
			return true, nil
		}
	}

	return false, nil
}

// nvdRateLimitInterval returns an interval to limit rate of requests
// to the NVD API. NVD allows 50 requests per 30-second window
// with an API key or 5 per 30 seconds without an API key.
// See https://nvd.nist.gov/developers/start-here for more information.
func nvdRateLimitInterval() time.Duration {
	window := 30 * time.Second
	if _, found := os.LookupEnv("NVD_API_KEY"); found {
		return window / 50 // 50 per 30 seconds (one request per 600ms)
	}

	return window / 5 // 5 per 30 seconds (one req per 6s)
}
