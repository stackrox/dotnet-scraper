module github.com/stackrox/dotnet-scraper

go 1.14

require (
	github.com/facebookincubator/nvdtools v0.1.4-0.20191024132624-1cb041402875
	github.com/ghodss/yaml v1.0.0
	github.com/google/go-github/v32 v32.1.0
	github.com/stretchr/testify v1.6.1
	gopkg.in/yaml.v2 v2.3.0 // indirect
)

replace github.com/facebookincubator/nvdtools => github.com/stackrox/nvdtools v0.0.0-20200903060121-ccc2b5ea9f6f
