package types

import (
	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
)

// CVEDefinition describes a CVE derived from the github issues page and
// is used to augment the NVD datasource
type CVEDefinition struct {
	ID               string                                `json:"id"`
	Link             string                                `json:"link"`
	AffectedPackages []*schema.NVDCVEFeedJSON10DefCPEMatch `json:"affectedPackages"`
	Description      string                                `json:"description"`
	Impact           *schema.NVDCVEFeedJSON10DefImpact     `json:"impact"`
}
