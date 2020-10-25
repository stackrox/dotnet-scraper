package cves

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"

	"github.com/ghodss/yaml"
	"github.com/stackrox/dotnet-scraper/types"
)

func TestParseYAMLs(t *testing.T) {
	files, err := ioutil.ReadDir(".")
	if err != nil {
		panic(err)
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".yaml" {
			continue
		}
		data, err := ioutil.ReadFile(f.Name())
		if err != nil {
			panic(err)
		}
		var ff types.FileFormat
		if err := yaml.Unmarshal(data, &ff); err != nil {
			panic(err)
		}
		if len(ff.AffectedPackages) == 0 {
			panic("argh")
		}
	}
}

type AffectedPackage struct {
	Name        string   `json:"name"`
	Constraints []string `json:"constraints"`
}

type FileFormat struct {
	ID               string                                `json:"id"`
	Link             string                                `json:"link"`
	AffectedPackages []*schema.NVDCVEFeedJSON10DefCPEMatch `json:"affectedPackages"`
}

type OldFileFormat struct {
	ID               string            `json:"id"`
	Link             string            `json:"link"`
	AffectedPackages []AffectedPackage `json:"affectedPackages"`
}

func TestRewriteFiles(t *testing.T) {
	files, err := ioutil.ReadDir(".")
	if err != nil {
		panic(err)
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".yaml" {
			continue
		}
		if !strings.Contains(f.Name(), "-new") {
			continue
		}
		if err := os.Rename(f.Name(), strings.ReplaceAll(f.Name(), "-new", "")); err != nil {
			panic(err)
		}
	}
}

func TestYAMLRewrite(t *testing.T) {
	files, err := ioutil.ReadDir(".")
	if err != nil {
		panic(err)
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".yaml" {
			continue
		}
		var off FileFormat
		data, err := ioutil.ReadFile(f.Name())
		if err != nil {
			fmt.Println(f.Name())
			panic(err)
		}
		if err := yaml.Unmarshal(data, &off); err != nil {
			fmt.Println(f.Name())
			panic(err)
		}

		var newFormat FileFormat
		newFormat.ID = off.ID
		newFormat.Link = off.Link

		//cpeFraming := "cpe:2.3:a:microsoft:%s:*:*:*:*:*:*:*:*"

		fmt.Println(off.ID)
		for _, pkg := range off.AffectedPackages {
			pkg.Cpe23Uri = strings.ToLower(pkg.Cpe23Uri)
		}

			newBytes, err := yaml.Marshal(&off)
			if err != nil {
				panic(err)
			}
			if err := ioutil.WriteFile(f.Name(), newBytes, 0777); err != nil {
				panic(err)
			}

		fmt.Println()

		/*
		   affectedPackages:
		   - constraints:
		     - cpe23URI: "cpe:2.3:a:microsoft:System.Text.Encodings.Web:4.0.0:*:*:*:*:*:*:*"
		     - cpe23URI: "cpe:2.3:a:microsoft:System.Text.Encodings.Web:4.3.0:*:*:*:*:*:*:*"

		     - cpe23URI: "cpe:2.3:a:microsoft:System.Net.Http:4.1.1:*:*:*:*:*:*:*"
		     - cpe23URI: "cpe:2.3:a:microsoft:System.Net.Http:4.3.1:*:*:*:*:*:*:*"

		     - cpe23URI: "cpe:2.3:a:microsoft:System.Net.Http.WinHttpHandler:4.0.1:*:*:*:*:*:*:*"
		     - cpe23URI: "cpe:2.3:a:microsoft:System.Net.Http.WinHttpHandler:4.3.1:*:*:*:*:*:*:*"

		     - cpe23URI: "cpe:2.3:a:microsoft:System.Net.Security:4.0.0:*:*:*:*:*:*:*"
		     - cpe23URI: "cpe:2.3:a:microsoft:System.Net.Security:4.3.0:*:*:*:*:*:*:*"

		     - cpe23URI: "cpe:2.3:a:microsoft:System.Net.WebSockets.Client:4.0.0:*:*:*:*:*:*:*"
		     - cpe23URI: "cpe:2.3:a:microsoft:System.Net.WebSockets.Client:4.3.0:*:*:*:*:*:*:*"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Core:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Core:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Abstractions:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Abstractions:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.ApiExplorer:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.ApiExplorer:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Cors:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Cors:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.DataAnnotations:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.DataAnnotations:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Formatters.Json:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Formatters.Json:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Formatters.Xml:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Formatters.Xml:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Localization:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Localization:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Razor.Host:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Razor.Host:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Razor:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.Razor:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.TagHelpers:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.TagHelpers:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.ViewFeatures:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.ViewFeatures:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"

		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.WebApiCompatShim:1.0.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.0.0"
		       versionEndExcluding: "1.0.4"
		     - cpe23URI: "cpe:2.3:a:microsoft:Microsoft.AspNetCore.Mvc.WebApiCompatShim:1.1.0:*:*:*:*:*:*:*"
		       versionStartIncluding: "1.1.0"
		       versionEndExcluding: "1.1.3"
		   id: CVE-2017-0247
		   link: https://github.com/dotnet/announcements/issues/12

		*/

	}
}
