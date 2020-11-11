package main

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/google/go-github/v32/github"
	"github.com/stackrox/dotnet-scraper/types"
)

type repoReference struct {
	owner, name string
}

const (
	pageSize = 20
)

var repos = []repoReference{
	{
		owner: "dotnet",
		name:  "announcements",
	},
	{
		owner: "aspnet",
		name:  "Announcements",
	},
}

// knownMissingLinks are links that exist in the github repos, but are not referred to by the YAML files
// this can be due to duplicate CVE definitions between dotnet and aspnet, issues that don't have CVEs attributed
// and advisories that are irrelevant
var knownMissingLinks = []string{
	// ASP.NET Announcement Repo

	// Microsoft Security Advisory: iOS12 breaks social, WSFed and OIDC logins #318
	"https://github.com/aspnet/Announcements/issues/318",
	// Microsoft Security Advisory ASPNETCore-July18: ASP.NET Core Denial Of Service Vulnerability
	"https://github.com/aspnet/Announcements/issues/311",
	// Microsoft Security Advisory ASPNETCore-Mar18: ASP.NET Core Denial Of Service Vulnerability
	"https://github.com/aspnet/Announcements/issues/300",
	// Microsoft Security Advisory CVE-2019-0815: ASP.NET Core denial of service vulnerability
	// Strange module
	"https://github.com/aspnet/Announcements/issues/352",
	// Microsoft Security Advisory 4021279: Vulnerabilities in .NET Core, ASP.NET Core Could Allow Elevation of Privilege
	// Duplicate of https://github.com/dotnet/announcements/issues/12
	"https://github.com/aspnet/Announcements/issues/239",
	// Microsoft Security Advisory CVE-2018-0808: ASP.NET Core Denial Of Service Vulnerability
	// IIS vuln
	"https://github.com/aspnet/Announcements/issues/294",
	// Microsoft Security Advisory CVE-2019-0548: ASP.NET Core Denial Of Service Vulnerability
	// IIS vuln
	"https://github.com/aspnet/Announcements/issues/335",
	// Ignoring MSAs for now
	"https://github.com/aspnet/Announcements/issues/203",
	"https://github.com/aspnet/Announcements/issues/216",
	// Affects .NET SDK
	"https://github.com/aspnet/Announcements/issues/284",
	"https://github.com/aspnet/Announcements/issues/285",

	// .NET Announcement Repo

	// Microsoft Security Advisory CVE-2020-1597 | ASP.NET Core Denial of Service Vulnerability
	// Duplicate
	"https://github.com/dotnet/announcements/issues/162",
	// Microsoft Security Advisory CVE-2018-8409: .NET Core Denial Of Service Vulnerability
	// Duplicate
	"https://github.com/dotnet/announcements/issues/83",
	// Microsoft Security Advisory CVE-2020-1108 | .NET Core Denial of Service Vulnerability
	// Duplicate of https://github.com/dotnet/announcements/issues/157
	"https://github.com/dotnet/announcements/issues/156",
}

func main() {
	client := github.NewClient(nil)

	issueLinks := make(map[string]bool)
	for _, repo := range repos {
		var issues []*github.Issue
		var page int
		for {
			pagedIssues, _, err := client.Issues.ListByRepo(context.Background(), repo.owner, repo.name, &github.IssueListByRepoOptions{
				Labels: []string{"security"},
				ListOptions: github.ListOptions{
					Page:    page,
					PerPage: pageSize,
				},
			})
			if err != nil {
				log.Fatalf("Could not fetch issues for %s/%s: %v", repo.owner, repo.name, err)
			}
			page++
			issues = append(issues, pagedIssues...)
			if len(pagedIssues) != pageSize {
				break
			}
		}

		for _, issue := range issues {
			title := strings.TrimSpace(issue.GetTitle())
			if !strings.HasPrefix(title, "Microsoft Security Advisory") {
				continue
			}
			link := strings.ReplaceAll(issue.GetURL(), "api.github.com/repos", "github.com")
			issueLinks[link] = true
		}
	}

	root := "cves"
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(info.Name()) == ".yaml" {
			bytes, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			var cd types.CVEDefinition
			if err := yaml.Unmarshal(bytes, &cd); err != nil {
				return err
			}
			_, ok := issueLinks[cd.Link]
			if !ok {
				log.Fatalf("unknown link %v - %v", cd.Link, info.Name())
			} else {
				issueLinks[cd.Link] = false
			}
		}
		return nil
	})
	if err != nil {
		log.Fatalf("error walking cve dir: %v", err)
	}

	// Remove all known missing links. Why the links are missing should be next to their declaration
	for _, knownMissing := range knownMissingLinks {
		delete(issueLinks, knownMissing)
	}
	if len(issueLinks) > 0 {
		fail := false
		for link, val := range issueLinks {
			if val {
				fail = true
				log.Printf("Unaccounted for issue: %v", link)
			}
		}
		if fail {
			log.Fatalf("Failing with non 0 exit code")
		}
	}
}
