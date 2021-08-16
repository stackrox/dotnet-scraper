package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
)

func validateNVDCVEIsEvaluated(cve string) (bool, error) {
	resp, err := http.Get(fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cve/1.0/%s", cve))
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
		return false, err
	}
	data, err = json.Marshal(respMap["result"])
	if err != nil {
		return false, err
	}

	var result schema.NVDCVEFeedJSON10
	if err := json.Unmarshal(data, &result); err != nil {
		return false, err
	}
	// CVE not stillNeeded
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
