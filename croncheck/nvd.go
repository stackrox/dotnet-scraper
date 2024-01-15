package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
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

	resp, err := http.Get(u.String())
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	respMap := make(map[string]interface{})

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, &respMap); err != nil {
		return false, fmt.Errorf("unmarshalling NVD response body: %w", err)
	}
	data, err = json.Marshal(respMap["result"])
	if err != nil {
		return false, err
	}

	var result schema.NVDCVEFeedJSON10
	if err := json.Unmarshal(data, &result); err != nil {
		return false, fmt.Errorf("unmarshalling NVD response result: %w", err)
	}
	// CVE not found
	if len(result.CVEItems) == 0 {
		return false, nil
	}
	if len(result.CVEItems) > 1 {
		return false, fmt.Errorf("unexpected number of CVE items (%d) for %s", len(result.CVEItems), cve)
	}
	fullCVE := result.CVEItems[0]
	if fullCVE.Impact.BaseMetricV2 == nil && fullCVE.Impact.BaseMetricV3 == nil {
		return false, nil
	}

	if fullCVE.Impact.BaseMetricV2 != nil && fullCVE.Impact.BaseMetricV2.CVSSV2 != nil {
		return true, nil
	}
	if fullCVE.Impact.BaseMetricV3 != nil && fullCVE.Impact.BaseMetricV3.CVSSV3 != nil {
		return true, nil
	}
	return false, nil
}
