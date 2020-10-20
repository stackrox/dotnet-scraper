package main

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/stackrox/dotnet-scraper/types"

	"github.com/google/go-github/v32/github"
)

type repoReference struct {
	owner, name string
}

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

var knownMissingLinks = []string{
	// Microsoft Security Advisory: iOS12 breaks social, WSFed and OIDC logins #318
	"https://github.com/aspnet/Announcements/issues/318",

	// Microsoft Security Advisory ASPNETCore-July18: ASP.NET Core Denial Of Service Vulnerability
	"https://github.com/aspnet/Announcements/issues/311",

	// Microsoft Security Advisory ASPNETCore-Mar18: ASP.NET Core Denial Of Service Vulnerability
	"https://github.com/aspnet/Announcements/issues/300",

	// Microsoft Security Advisory CVE-2020-1597 | ASP.NET Core Denial of Service Vulnerability
	// Duplicate
	"https://github.com/dotnet/announcements/issues/162",

	// Microsoft Security Advisory CVE-2019-0815: ASP.NET Core denial of service vulnerability
	// Strange module
	"https://github.com/aspnet/Announcements/issues/352",

	// Microsoft Security Advisory CVE-2020-1108 | .NET Core Denial of Service Vulnerability
	// Duplicate of "https://github.com/dotnet/announcements/issues/157"
	"https://github.com/dotnet/announcements/issues/156",

	// Microsoft Security Advisory 4021279: Vulnerabilities in .NET Core, ASP.NET Core Could Allow Elevation of Privilege
	// Duplicate of https://github.com/dotnet/announcements/issues/12
	"https://github.com/aspnet/Announcements/issues/239",

	// Microsoft Security Advisory CVE-2018-0808: ASP.NET Core Denial Of Service Vulnerability
	// IIS vuln
	"https://github.com/aspnet/Announcements/issues/294",
}

func main() {
	client := github.NewClient(nil)

	issueLinks := make(map[string]bool)
	for _, repo := range repos {
		issues, _, err := client.Issues.ListByRepo(context.Background(), repo.owner, repo.name, &github.IssueListByRepoOptions{
			Labels: []string{"security"},
			ListOptions: github.ListOptions{
				Page:    0,
				PerPage: 500,
			},
		})
		if err != nil {
			log.Fatalf("Could not fetch issues for %s/%s: %v", repo.owner, repo.name, err)
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
			bytes, err := ioutil.ReadFile(filepath.Join(root, info.Name()))
			if err != nil {
				return err
			}
			ff := &types.FileFormat{}
			if err := yaml.Unmarshal(bytes, ff); err != nil {
				log.Fatalf("could not parse yaml file %s: %v", info.Name(), err)
			}
			_, ok := issueLinks[ff.Link]
			if !ok {
				log.Fatalf("unknown link %v - %v", ff.Link, info.Name())
			} else {
				issueLinks[ff.Link] = false
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
