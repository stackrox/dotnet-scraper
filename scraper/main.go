package main

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/google/go-github/v32/github"
)

type affectedPackage struct {
	Name        string   `json:"name"`
	Constraints []string `json:"constraints"`
}

type fileFormat struct {
	ID               string            `json:"id"`
	Link             string            `json:"link"`
	AffectedPackages []affectedPackage `json:"affectedPackages"`
}

type repo struct {
	owner, name string
}

var (
	reposToScrape = []repo{
		{
			owner: "dotnet",
			name:  "announcements",
		},
		{
			owner: "aspnet",
			name:  "Announcements",
		},
	}
)

func prompt(p string) string {
	fmt.Printf("%s: ", p)
	scanner := bufio.NewScanner(os.Stdin)

	scanner.Scan()
	return scanner.Text()
}

func readData(issue *github.Issue) {
	ff := fileFormat{}
	ff.ID = prompt("Enter ID")
	ff.Link = issue.GetURL()

	for {
		var pkg affectedPackage
		pkg.Name = prompt("pkg")
		if pkg.Name == "done" {
			break
		}
		for {
			constraint := prompt("Enter constraint")
			if constraint == "done" {
				break
			}
			pkg.Constraints = append(pkg.Constraints, constraint)
		}
		ff.AffectedPackages = append(ff.AffectedPackages, pkg)
	}

	data, err := yaml.Marshal(ff)
	if err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(ff.ID+".yaml", data, 0777); err != nil {
		panic(err)
	}
}

func main() {
	client := github.NewClient(nil)

	issueLink := make(map[string]struct{})
	for _, repo := range reposToScrape {
		issues, _, err := client.Issues.ListByRepo(context.Background(), repo.owner, repo.name, &github.IssueListByRepoOptions{
			Labels: []string{"security"},
			ListOptions: github.ListOptions{
				Page:    0,
				PerPage: 500,
			},
		})
		if err != nil {
			panic(err)
		}

		for _, issue := range issues {
			if !strings.HasPrefix(issue.GetTitle(), "Microsoft Security Advisory") {
				continue
			}
			link := strings.ReplaceAll(issue.GetURL(), "api.github.com/repos", "github.com")
			issueLink[link] = struct{}{}
		}

		err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
			if filepath.Ext(info.Name()) == ".yaml" {
				bytes, err := ioutil.ReadFile(info.Name())
				if err != nil {
					return err
				}
				ff := &fileFormat{}
				if err := yaml.Unmarshal(bytes, ff); err != nil {
					fmt.Println("MEEP", info.Name())
					return err
				}
				l := len(issueLink)
				delete(issueLink, ff.Link)
				if len(issueLink) != l {
					//fmt.Println("Removed", ff.Link)
				}
			}
			return nil
		})
		if err != nil {
			panic(err)
		}

		//
		//fmt.Printf("Repo: %s %s\n", repo.owner, repo.name)
		//for _, issue := range issues {
		//	if !strings.HasPrefix(issue.GetTitle(), "Microsoft Security Advisory") {
		//		continue
		//	}
		//
		//	body := issue.GetBody()
		//
		//	startIdx := strings.Index(body, `<a name="affected-software">`)
		//	if startIdx == -1 {
		//		fmt.Printf("\t%s: could not derive data: %v\n", issue.GetTitle(), issue.GetBody())
		//		readData(issue)
		//		continue
		//	}
		//
		//	body = body[startIdx+len(`<a name="affected-software">`):]
		//	endIdx := strings.Index(body, "<a")
		//	if endIdx != -1 {
		//		body = body[:endIdx]
		//	} else {
		//		fmt.Printf("\t%s: could not derive data: %v\n", issue.GetTitle(), issue.GetBody())
		//		readData(issue)
		//		continue
		//	}
		//	body = strings.ReplaceAll(body, "Please note that .NET Core 3.0 is now out of support and all applications should be updated to 3.1.", "")
		//	fmt.Printf("\t%s: Data: %v\n", issue.GetTitle(), body)
		//	readData(issue)
		//}
	}

	for l := range issueLink {
		fmt.Println(l)
	}
}
