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
import csv
import json
import re
from github import GithubException

token = os.environ["GITHUB_TOKEN"]

PER_PAGE = 100

HTML_OUT = "public/index.html"
HTML_PRE = "index.html.pre"
HTML_POST = "index.html.post"

PASS = "<span class=approved>&check;</span>"
FAIL = "<span class=blocked>&#10005;</span>"

UTC = datetime.timezone.utc

NXP_Zephyr_Team = [
    # "dleach02",
    # ]

# NXP_Zephyr_Team2 = [

    "0xFarahFl",
    "abhinavnxp",
    "agansari",
    "Albort12138",
    "aleguka",
    "alexandru-porosanu-nxp",
    "alrodlim",
    "alxlastur",
    "anaGrad",
    "andrei-menzopol",
    "andreicatalin-ilie-nxp",
    "andrisk-dev",
    "ankeXiao",
    "asellaminxp",
    "axelnxp",
    "botan-nxp",
    "butok",
    "caiohbm",
    "camelia-groza-NXP",
    "CanWang001",
    "CC0918",
    "ChangNice",
    "ChayGuo",
    "CherQin",
    "congnguyenhuu",
    "cosmindanielradu19",
    "Dat-NguyenDuy",
    "davidmissael",
    "dbaluta",
    "decsny",
    "DerekSnell",
    "dleach02",
    "dpiskula-nxp",
    "Dv-Alan-NXP",
    "EmilioCBen",
    "FelixWang47831",
    "fengming-ye",
    "fgoucemnxp",
    "flora2086",
    "gangli02",
    "GaofengZhangNXP",
    "George-Stefan",
    "groncarolonxp",
    "haduongquang",
    "hakehuang",
    "ilie-halip-nxp",
    "irtrukhina",
    "iuliana-prodan",
    "JA-NXP",
    "jacob-wienecke-nxp",
    "JanKomarekNXP",
    "jerryyang35",
    "JesseSamuel",
    "JiafeiPan",
    "jirioc",
    "JoshPPrieto",
    "JulienJouanNXP",
    "junzhuimx",
    "KATE-WANG-NXP",
    "KavitaSharma-14",
    "kshitizvars",
    "laurenpost",
    "LaurentiuM1234",
    "LiLongNXP",
    "Liubin-glb",
    "liugang-gavin",
    "lucien-nxp",
    "LuisC-NXP",
    "luozhenhua",
    "lylezhu2012",
    "makeshi",
    "manuargue",
    "MaochenWang1",
    "MarkWangChinese",
    "mayankmahajan-nxp",
    "McuxCIBot",
    "mcuxted",
    "meghana-nxp",
    "mgalda82",
    "michal-smola",
    "MichalPrincNXP",
    "mmahadevan108",
    "MrVan",
    "neenareddi",
    "NeilChen93",
    "NGExplorer",
    "ngphibang",
    "nicusorcitu",
    "nirav-agrawal",
    "nngt88",
    "nxa18843",
    "nxf58150",
    "nxf86985",
    "nxf91057",
    "NXP-Liam-Li",
    "nxp-shelley",
    "nxp-wayne",
    "pavel-macenauer-nxp",
    "PetervdPerk-NXP",
    "peterwangsz",
    "Pop-korn",
    "prabhusundar",
    "Qingling-Wu",
    "quangbuitrong",
    "Radimli",
    "Raymond0225",
    "ReneThrane",
    "Rex-Chen-NXP",
    "riestmo-nxp",
    "Ritesh-nxp",
    "robert-kalmar",
    "RuoshanShi",
    "sahilnxp",
    "sanjay-yadav-nxp",
    "saurabh-nxp",
    "skywall",
    "stanislav-poboril",
    "sumitbatra-nxp",
    "SuperHeroAbner",
    "sviaunxp",
    "tcsunhao",
    "thochstein",
    "Tim-Wang38",
    "TomasBarakNXP",
    "TomasGalbickaNXP",
    "trunghieulenxp",
    "tsi-chung",
    "tunguyen4585",
    "valijec",
    "VitekST",
    "william-tang914",
    "xavraz",
    "XChunlei",
    "xinyu0322",
    "yangbolu1991",
    "yeaissa",
    "yongxu-wang15",
    "yvesll",
    "yyounxp",
    "zejiang0jason",
    "zelan-nxp",
    "ZhaoQiang-b45475",
    "ZhaoxiangJin",
    "Zhiqiang-Hou",
    "ZongchunYu",


    #
    # These were on the old list but don't currently show up in the new nxp-upstream list.
    # Probably because they are submitting from their own private repository (bad)
    #
    "vakulgarg", "Ursescu",
    "Lucien-Zhao",
    "bperseghetti",
    "igalloway", 

    # continue monitoring Daniel's PR
    #"danieldegrasse",

    ]

class NXP_Zephyr:
    '''
        NXP ORG
    '''
    def __init__(self):
        '''
            init
        '''
        self.NXP_Zephyr_Team = []

    def update(self, _gh, team_list = NXP_Zephyr_Team, team_slug = "nxp-zephyr-write"):
        '''
            update team members
        '''
        # org = _gh.get_organization("nxp-zephyr")
        # #fixme no access for integartion, has to hard code here
        # try:
            # teams = org.get_teams()
            # for _t in teams:
                # if _t.name == team_slug:
                    # for _m in _t.get_members():
                        # print(_m.login)
                        # self.NXP_Zephyr_Team.insert(_m.login)
        # except Exception as _e:
            # print(f"{_e}")
            # print("fallback to hardcode version")
        def sort_key(x):
            print(f"Processing element: {x}")
            return str(x).lower()

        self.NXP_Zephyr_Team += sorted(team_list, key=lambda x: x.lower())
        #self.NXP_Zephyr_Team += sorted(team_list, key=sort_key)

        print(f"NXP_Zephyr: {self.NXP_Zephyr_Team}")

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


def evaluate_criteria(number, data):
    pr = data.pr
    author = pr.user.login
    labels = [l.name for l in pr.labels]
    assignees = [a.login for a in pr.assignees]
    mergeable = pr.mergeable
    hotfix = "Hotfix" in labels
    trivial = "Trivial" in labels
    change_request = False

    approvers = set()
    changes = set()
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

    if changes:
        change_request = True

    assignee_approved = False

    if (hotfix or
        not assignees or
        author in assignees):
        assignee_approved = True

    for approver in approvers:
        if approver in assignees:
            assignee_approved = True

    reference_time = pr.created_at
    for event in data.pr.get_issue_events():
        if event.event == 'ready_for_review':
            reference_time = event.created_at
    now = datetime.datetime.now(UTC)

    delta = now - reference_time.astimezone(UTC)
    delta_hours = int(delta.total_seconds() / 3600)
    delta_biz_hours = calc_biz_hours(reference_time.astimezone(UTC), delta)

    if hotfix:
        time_left = 0
    elif trivial:
        time_left = 4 - delta_hours
    else:
        time_left = 48 - delta_biz_hours

    data.assignee = assignee_approved
    data.approvers = approvers
    data.time = time_left <= 0
    data.time_left = time_left
    data.mergeable = mergeable
    data.hotfix = hotfix
    data.trivial = trivial
    data.change_request = change_request

    data.debug = [pr.number, author, assignees, approvers, delta_hours,
                  delta_biz_hours, time_left, mergeable, hotfix, trivial,
                  change_request]


def table_entry(number, data, html=True):
    pr = data.pr
    url = pr.html_url
    title = pr.title
    author = pr.user.login
    assignees = ', '.join(sorted(a.login for a in pr.assignees))

    approvers_set = data.approvers
    approvers = ', '.join(sorted(data.approvers))

    base = pr.base.ref
    if pr.milestone:
        milestone = pr.milestone.title
    else:
        milestone = ""

    mergeable = PASS if data.mergeable else FAIL
    assignee = PASS if data.assignee else FAIL
    time = PASS if data.time else FAIL + f" {data.time_left}h left"

    if data.change_request:
        tr_class = "change"
    elif data.mergeable and data.assignee and data.time:
        tr_class = ""
    else:
        tr_class = "draft"

    tags = []
    if data.hotfix:
        tags.append("H")
    if data.trivial:
        tags.append("T")
    if data.change_request:
        tags.append("C")
    tags_text = ' '.join(tags)

    if html:
        return f"""
            <tr class="{tr_class}">
                <td><a href="{url}">{pr.number}</a></td>
                <td><a href="{url}">{title}</a></td>
                <td>{author}</td>
                <td>{assignees}</td>
                <td>{approvers}</td>
                <td>{base}</td>
                <td>{milestone}</td>
                <td>{mergeable}</td>
                <td>{assignee}</td>
                <td>{time}</td>
                <td>{tags_text}</td>
            </tr>
            """
    else:
        return f"""{pr.number},{title},{author},{url}"""


def table_entry_csv(data):
    pr = data.pr
    print(pr)
    return { 'PR#' : pr.number, 'Title' : pr.title, 'Author' : pr.user.login, 'URL': pr.html_url }


def repo_entry(repo_name):
    return f"""
        <tr>
            <th></th>
            <th colspan="10">{repo_name}</th>
        </tr>
        """


def query_repo(gh, nxp, org, repo, ignore_milestones):
    pr_data = []

    pattern = r"github\.com/([^/]+)/([^/]+)/"

    for user in nxp.NXP_Zephyr_Team:
        #query = f"is:pr is:open repo:{org}/{repo} author:{user}"
        query = f"is:pr is:open org:{org} author:{user}"
        print(query)

        try:
            pr_issues = gh.search_issues(query=query)
            for issue in pr_issues:
                if issue.milestone and issue.milestone.title in ignore_milestones:
                    print(f"ignoring: {number} milestone={issue.milestone.title}")
                    continue

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
            continue

    print("Evaluate PR list")
    for data in pr_data:
        evaluate_criteria(0, data)

    debug_headers = ["number", "author", "assignees", "approvers",
                     "delta_hours", "delta_biz_hours", "time_left", "Mergeable",
                     "Hotfix", "Trivial", "Change"]
    debug_data = []
    for data in pr_data:
        debug_data.append(data.debug)
    print(tabulate.tabulate(debug_data, headers=debug_headers))

    return pr_data


def query_merged(gh, nxp, org, from_date):
    pr_data = []

    pattern = r"github\.com/([^/]+)/([^/]+)/"

    for user in nxp.NXP_Zephyr_Team:
        query = f"is:pr is:merged org:{org} author:{user} merged:>{from_date}"
        print(query)

        try:
            #print_rate_limit(gh, org)
            pr_issues = gh.search_issues(query=query)
            for issue in pr_issues:
                print_rate_limit(gh, org)

                number = issue.number
                pr = issue.as_pull_request()
                matches = re.search(pattern, pr.html_url)
                print(f"fetch: {number}, org: {matches.group(1)}, repo: {matches.group(2)}")
                pr_data.append(PRData(issue=issue, pr=pr, repo=matches.group(2)))
        except Exception as e:
            if e.status== 422:
                print(f"Can't fetch {user}! Is account private?")
            continue
    return pr_data


def merged_count(gh, nxp, org, from_date):
    pr_data = []

    pattern = r"github\.com/([^/]+)/([^/]+)/"
    count = 0

    for user in nxp.NXP_Zephyr_Team:
        query = f"is:pr is:merged org:{org} author:{user} merged:>{from_date}"
        print(query)

        try:
            pr_issues = gh.search_issues(query=query)
            for issues in pr_issues:
                count += 1
        except Exception as e:
            if e.status== 422:
                print(f"Can't fetch {user}! Is account private?")
            continue
    return count

def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("-o", "--org", default="zephyrproject-rtos",
                        help="Github organisation")
    parser.add_argument("-r", "--repo", default="zephyr",
                        help="Github repository")
    parser.add_argument("-i", "--ignore-milestones", default="",
                        help="Comma separated list of milestones to ignore")
    parser.add_argument("--report", action='store_true',
                        help="generate csv report of current outstanding PRs")
    parser.add_argument("--merged", action='store_true',
                        help="generate csv merge report (needs -d / --date)")
    parser.add_argument("-d", "--date", default=datetime.date.today() - datetime.timedelta(days=7),
                        help="date value: YYYY-MM-DD format")
    parser.add_argument("-u", "--user", default="", type=str,
                        help="Specifiy a specific user to parse")
    parser.add_argument("--csv", default="pr_report.csv",
                        help="Output report file.")


    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)

    token = os.environ.get('GITHUB_TOKEN', None)
    gh = github.Github(token, per_page=PER_PAGE)

    print_rate_limit(gh, args.org)

    nxp = NXP_Zephyr()
    if args.user == "":
        nxp.update(gh)
    else:
        zork = args.user.split(',')
        print(zork)
        nxp.update(gh, team_list = args.user.split(','))

    pr_data = {}
    repo_list = ["zephyr", "hal_nxp", "hostap", "mbedtls", "mcuboot", "trusted-firmware-m", "tf-m-tests", "lvgl", "west",  ]

    if args.ignore_milestones:
        ignore_milestones = args.ignore_milestones.split(",")
        print(f"ignored milestones: {ignore_milestones}")
    else:
        ignore_milestones = []
    print(f"date: {args.date}")

    if args.merged:
        print(f"generate merge report since {args.date}")

        pr_data = query_merged(gh, nxp, args.org, args.date)
        pr_list = []

        for repo in repo_list:
            print(f"searching for {repo} PRs")
            matching_pr_data = [pr_instance for pr_instance in pr_data if pr_instance.repo == repo]
            if matching_pr_data:
                for pr_item in matching_pr_data:
                    print(pr_item)
                    pr_list.append(table_entry_csv(pr_item))

        header_fields = ['PR#', 'Title', 'Author', 'URL']

        with open(args.csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header_fields)
            writer.writeheader()
            writer.writerows(pr_list)

        return

    # Get current list of outstanding PRs
    pr_data = query_repo(gh, nxp, args.org, "zephyr", ignore_milestones)
    open_pr_count = len(pr_data)

    if args.report:
        print(f"Generate {args.csv} report")
        pr_list = []
        for repo in repo_list:
            print(f"searching for {repo} PRs")
            matching_pr_data = [pr_instance for pr_instance in pr_data if pr_instance.repo == repo]
            if matching_pr_data:
                for pr_item in matching_pr_data:
                    #print(pr_item)
                    pr_list.append(table_entry_csv(pr_item))

        header_fields = ['PR#', 'Title', 'Author', 'URL']

        with open(args.csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header_fields)
            writer.writeheader()
            writer.writerows(pr_list)

        return

    # Generate web page dashboard
    with open(HTML_PRE) as f:
        html_out = f.read()
        timestamp = datetime.datetime.now(UTC).strftime("%d/%m/%Y %H:%M:%S %Z")
        html_out = html_out.replace("UPDATE_TIMESTAMP", timestamp)

    for repo in repo_list:
        print(f"searching for {repo} PRs")
        matching_pr_data = [pr_instance for pr_instance in pr_data if pr_instance.repo == repo]
        if matching_pr_data:
            html_out += repo_entry(repo)
            for pr_item in matching_pr_data:
                html_out += table_entry(pr_item.pr.number, pr_item)

    merge_count = merged_count(gh, nxp, args.org, datetime.date.today() - datetime.timedelta(days=7))

    with open(HTML_POST) as f:
        html_out += f.read()
        html_out = html_out.replace("MERGE_COUNT", str(merge_count))
        html_out = html_out.replace("OPEN_COUNT", str(open_pr_count))

    with open(HTML_OUT, "w") as f:
        f.write(html_out)

    print_rate_limit(gh, args.org)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
