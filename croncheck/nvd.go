package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

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
	// resp, err := http.Get(u.String())
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
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
