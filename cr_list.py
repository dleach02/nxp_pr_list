#!/usr/bin/env python3

#
# Originally sourced from work by Fabio Baltieri <fabiobaltieri@google.com>. 
# Modified to only show NXP developers.
#
# The work is now part of Zephyr Project here: 
# https://github.com/zephyrproject-rtos/zephyr-merge-list
#
# Copyright 2024 Google LLC
# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0


from dataclasses import dataclass, field
import argparse
import datetime
import github
import os
import sys
import tabulate
import json
import re
from github import GithubException

token = os.environ["GITHUB_TOKEN"]

PER_PAGE = 100

HTML_OUT = "public/index_cr.html"
HTML_PRE = "index_cr.html.pre"
HTML_POST = "index_cr.html.post"

PASS = "<span class=approved>&check;</span>"
FAIL = "<span class=blocked>&#10005;</span>"

UTC = datetime.timezone.utc

@dataclass
class PRData:
    issue: github.Issue
    pr: github.PullRequest
    repo: str = field(default=None)
    assignee: str = field(default=None)
    approvers: set = field(default=None)
    time: bool = field(default=False)
    time_left: int = field(default=None)
    mergeable: bool = field(default=False)
    hotfix: bool = field(default=False)
    trivial: bool = field(default=False)
    change_request: bool = field(default=False)
    debug: list = field(default=None)


def print_rate_limit(gh, org):
    response = gh.get_organization(org)
    for header, value in response.raw_headers.items():
        if header.startswith("x-ratelimit"):
            print(f"{header}: {value}")


def calc_biz_hours(ref, delta):
    biz_hours = 0

    for hours in range(int(delta.total_seconds() / 3600)):
        date = ref + datetime.timedelta(hours=hours+1)
        if date.weekday() < 5:
            biz_hours += 1

    return biz_hours


def table_entry(number, data):
    pr = data.pr
    url = pr.html_url
    title = pr.title
    author = pr.user.login
    assignees = ', '.join(sorted(a.login for a in pr.assignees))

    approvers_set = data.approvers
    approvers = ', '.join(sorted(data.approvers))
    tr_class = "change"

    return f"""
        <tr class="{tr_class}">
            <td><a href="{url}">{pr.number}</a></td>
            <td><a href="{url}">{title}</a></td>
            <td>{author}</td>
            <td>{assignees}</td>
            <td>{approvers}</td>
        </tr>
        """

def query_user(gh, org, user):
    pr_data = []

    pattern = r"github\.com/([^/]+)/([^/]+)/"

    query = f"is:pr is:open review:changes_requested reviewed-by:{user}"
    print(query)
    try:
        pr_issues = gh.search_issues(query=query)
        print(pr_issues)
        for issue in pr_issues:
            number = issue.number
            pr = issue.as_pull_request()
            matches = re.search(pattern, pr.html_url)
            print(f"fetch: {number}, org: {matches.group(1)}, repo: {matches.group(2)}")
            if matches.group(1) == org:
                pr_data.append(PRData(issue=issue, pr=pr, repo=matches.group(2)))
            else:
                continue
    except Exception as e:
        if e.status== 422:
            print(f"Can't fetch {user}! Is account private?")

    print("Evaluate PR list")
    change_set = []
    for data in pr_data:
        #print(data)
        approvers = set()
        changes = set()
        assignees = [a.login for a in data.pr.assignees]

        for review in data.pr.get_reviews():
            if review.user:
                if review.state == 'APPROVED':
                    approvers.add(review.user.login)
                    changes.discard(review.user.login)
                elif review.state == 'CHANGES_REQUESTED':
                    approvers.discard(review.user.login)
                    changes.add(review.user.login)
                elif review.state == 'DISMISSED':
                    approvers.discard(review.user.login)
                    changes.discard(review.user.login)
        #print(changes)
        if user in changes:
            data.approvers = approvers
            data.debug = [data.pr.number, data.repo, data.pr.user.login, assignees, approvers]
            change_set.append(data)

    debug_headers = ["number", "repo", "author", "assignees", "approvers"]
    debug_data = []
    for data in change_set:
        debug_data.append(data.debug)
    print(tabulate.tabulate(debug_data, headers=debug_headers))

    return change_set


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("-o", "--org", default="zephyrproject-rtos",
                        help="Github organisation")
    parser.add_argument("-r", "--repo", default="zephyr",
                        help="Github repository")
    parser.add_argument("-u", "--user", default="",
                        help="GitHub user account to query")

    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)

    token = os.environ.get('GITHUB_TOKEN', None)
    gh = github.Github(token, per_page=PER_PAGE)

    pr_data = {}

    with open(HTML_PRE) as f:
        html_out = f.read()
        html_out = html_out.replace("USER_NAME", args.user)

    #repo_list = ["zephyr", "hal_nxp", "hostap", "mbedtls", "mcuboot", "trusted-firmware-m", "tf-m-tests", "lvgl", "west" ]
    pr_data = query_user(gh, args.org, args.user)

    print(len(pr_data))
    for pr_item in pr_data:
        html_out += table_entry(pr_item.pr.number, pr_item)
               
    with open(HTML_POST) as f:
        html_out += f.read()
        html_out = html_out.replace("CR_COUNT", str(len(pr_data)))

    with open(HTML_OUT, "w") as f:
        f.write(html_out)

    print_rate_limit(gh, args.org)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
