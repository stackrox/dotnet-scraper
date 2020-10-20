package types

type AffectedPackage struct {
	Name        string   `json:"name"`
	Constraints []string `json:"constraints"`
}

type FileFormat struct {
	ID               string            `json:"id"`
	Link             string            `json:"link"`
	AffectedPackages []AffectedPackage `json:"affectedPackages"`
}
