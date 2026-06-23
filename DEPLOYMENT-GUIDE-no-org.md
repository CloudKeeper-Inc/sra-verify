# SRA Verify — Deployment & Usage Guide (multi-account, no AWS Organizations)

This guide deploys and runs the **org-independent** build of SRA Verify: it scans an explicit list of member accounts, makes **no AWS Organizations API calls**, needs **no delegated administrator**, and reports Org/delegated-admin checks as **`INSUFFICIENT_DATA`** instead of misleading failures.

- 63 per-account (`application`) checks → real **PASS / FAIL**.
- 95 Org/delegated-admin checks → **`INSUFFICIENT_DATA`** ("not assessable in this deployment").

---

## 0. Prerequisites

| Requirement | Detail |
|---|---|
| **Scanning account** | One account where the scan runs (CodeBuild). Can be one of the targets or a separate tooling account. |
| **Target accounts** | The member account IDs to scan (e.g. your 5 accounts). |
| **Permissions to deploy** | Ability to deploy CloudFormation in the scanning account and in each target account (self-managed — no Org delegated admin needed). |
| **A fork of this code** | **Critical:** the org-independent features (`INSUFFICIENT_DATA`, `--no-org-access`, `ScanMode`) are **not** in upstream `awslabs/sra-verify`. You must host this modified repo somewhere CodeBuild can `git clone` (GitHub fork, CodeCommit, etc.) and point `SourceRepoUrl` at it. |
| **Templates** | `1-sraverify-member-roles.yaml` and `2-sraverify-codebuild-deploy-no-org.yaml`. Host on S3 or deploy from local files. |

> **Why the fork matters:** The CodeBuild buildspec installs SRA Verify by cloning `SourceRepoUrl`. If that points at upstream, `--no-org-access` and `ScanMode=AllWithInsufficientData` will fail because upstream doesn't have them. Push this repository (with the changes) to your own Git remote and use that URL.

---

## 1. Architecture (what assumes what)

```
                 Scanning account
        ┌────────────────────────────────┐
        │  CodeBuild (SRAVerifyCodeBuild  │
        │  ServiceRole)                   │
        │     │ assumes SRAMemberRole     │
        └─────┼──────────────────────────┘
              │ sts:AssumeRole (account-scoped trust, no PrincipalOrgID)
    ┌─────────┼──────────┬──────────┬──────────┐
    ▼         ▼          ▼          ▼          ▼
 Acct A    Acct B     Acct C     Acct D     Acct E
 SRAMemberRole (read-only) in each target account
```

- `SRAMemberRole` (in each target account) is **read-only** and trusts only the `SRAVerifyCodeBuildServiceRole` in the scanning account. No Organizations trust, no delegated admin.
- The scan runs per account in parallel, consolidates the CSVs, and uploads results + dashboard to S3.

---

## 2. Step 1 — Host the modified code (one-time)

Push this repository to a Git remote CodeBuild can reach:

```bash
# example: your fork
git remote add seekho https://github.com/CloudKeeper-Inc/sra-verify.git
git push seekho main
```

Note the URL and branch — you'll pass them as `SourceRepoUrl` / `GitBranch`.

> If you use a private repo, ensure CodeBuild can authenticate (CodeConnections/credentials). A public fork or AWS CodeCommit in the scanning account is simplest.

---

## 3. Step 2 — Deploy the member role into each target account

Deploy `1-sraverify-member-roles.yaml` into **every** target account. `SRAVerifyAccountID` = the **scanning** account ID.

**Per account (from local file):**
```bash
aws cloudformation deploy \
  --template-file 1-sraverify-member-roles.yaml \
  --stack-name sraverify-member-role \
  --parameter-overrides SRAVerifyAccountID=<SCANNING_ACCOUNT_ID> \
  --capabilities CAPABILITY_NAMED_IAM \
  --profile <profile-for-that-account>
```

**Or from a hosted template (S3 URL):**
```bash
aws cloudformation create-stack \
  --stack-name sraverify-member-role \
  --template-url https://<bucket>.s3.<region>.amazonaws.com/1-sraverify-member-roles.yaml \
  --parameters ParameterKey=SRAVerifyAccountID,ParameterValue=<SCANNING_ACCOUNT_ID> \
  --capabilities CAPABILITY_NAMED_IAM \
  --region <region> --profile <profile-for-that-account>
```

Repeat for each target account, **or** deploy once as a **self-managed StackSet** with the target account IDs as explicit targets. The role trust is account-scoped, so no Org trusted access is required.

> The role already grants every read permission the checks need (guardduty, config, s3, ec2, iam, wafv2, shield, macie2, inspector2, access-analyzer, securityhub, account, sts). Nothing to add.

---

## 4. Step 3 — Deploy the CodeBuild stack (scanning account)

Deploy `2-sraverify-codebuild-deploy-no-org.yaml` **once** in the scanning account.

### Parameters

| Parameter | Required | Notes |
|---|---|---|
| `TargetAccountIDs` | ✅ | Comma-separated account IDs to scan. Replaces `organizations:ListAccounts`. |
| `SourceRepoUrl` | ✅ | **Your fork URL** (the modified code). Default points at upstream — change it. |
| `GitBranch` | | Branch of your fork (default `main`). |
| `ScanMode` | | `ApplicationOnly` (default) or `AllWithInsufficientData` (see §6). |
| `IncludeRegions` | | Comma-separated regions (default `us-east-1,us-east-2,us-west-2`). |
| `ParallelAccounts` | | Concurrency (default 5). |
| `AuditAccountID` / `LogArchiveAccountID` | | Leave **blank** for Seekho (no delegated admins). Only used in `ApplicationOnly` mode if a real delegated-admin account exists. |

### Recommended deploy (clean per-account report)
```bash
aws cloudformation deploy \
  --template-file 2-sraverify-codebuild-deploy-no-org.yaml \
  --stack-name sraverify \
  --parameter-overrides \
    TargetAccountIDs=111111111111,222222222222,333333333333,444444444444,555555555555 \
    SourceRepoUrl=https://github.com/CloudKeeper-Inc/sra-verify.git \
    GitBranch=main \
    ScanMode=ApplicationOnly \
    IncludeRegions=us-east-1,us-west-2 \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --region <region> --profile <scanning-account-profile>
```

### Complete report (org checks shown as Insufficient Data)
Set `ScanMode=AllWithInsufficientData` instead — every check appears, with the 95 Org/delegated-admin checks marked `INSUFFICIENT_DATA`.

> **Deploy member roles (Step 2) first.** The scan **auto-starts** on stack create, so the roles must already exist in the target accounts.

---

## 5. Step 4 — The scan runs automatically; monitor it

A custom-resource Lambda starts the CodeBuild job on stack **create** (no manual step).

```bash
# find the build
aws codebuild list-builds-for-project --project-name SRAVerify-Security-Assessment \
  --region <region> --profile <scanning-account-profile>

# check status
aws codebuild batch-get-builds --ids <build-id> \
  --query 'builds[0].buildStatus' --region <region> --profile <scanning-account-profile>
```
Or watch it in the CodeBuild console (project `SRAVerify-Security-Assessment`).

> **Re-running later:** the auto-start fires only on stack *create*. After a parameter change (`update-stack`) or to re-scan on demand, start it manually:
> ```bash
> aws codebuild start-build --project-name SRAVerify-Security-Assessment \
>   --region <region> --profile <scanning-account-profile>
> ```

---

## 6. Scan modes explained

| Mode | What runs per account | Report contents |
|---|---|---|
| **ApplicationOnly** (default) | `sraverify --account-type application` | The 63 per-account checks only → clean PASS/FAIL, no noise. |
| **AllWithInsufficientData** | `sraverify --account-type all --no-org-access` | All 158 checks → 63 PASS/FAIL + 95 `INSUFFICIENT_DATA`. |

- Use **ApplicationOnly** when you want a lean, actionable report.
- Use **AllWithInsufficientData** when stakeholders want to *see* that the Org-level controls were considered but couldn't be assessed (self-documenting coverage).

---

## 7. Step 5 — Retrieve the results

Find the results bucket (name contains `bucketsraverifyfindings`):
```bash
aws cloudformation describe-stack-resources --stack-name sraverify \
  --query "StackResources[?ResourceType=='AWS::S3::Bucket'].PhysicalResourceId" \
  --output text --region <region> --profile <scanning-account-profile>
```

Layout:
```
s3://<bucket>/sraverify/reports/raw/            # per-account CSVs
s3://<bucket>/sraverify/reports/consolidated/   # consolidated CSV + sra-verify-dashboard.html
```

### View the dashboard
1. In S3, open `sraverify/reports/consolidated/sra-verify-dashboard.html`.
2. Generate a **presigned URL** for the consolidated CSV (Actions → Share with presigned URL, ~1 min).
3. Paste the URL into the dashboard's "Load URL" box.

The dashboard now shows an **Insufficient Data** count card, a status filter for it, and gray badges — so those rows are visibly distinct from failures.

---

## 8. Running locally (alternative / quick first pass)

No CodeBuild needed — run from any machine with credentials that can assume `SRAMemberRole`:

```bash
pip install ./sraverify

ACCTS="111111111111 222222222222 333333333333 444444444444 555555555555"
REGIONS="us-east-1,us-west-2"
mkdir -p out

for a in $ACCTS; do
  sraverify --role arn:aws:iam::$a:role/SRAMemberRole \
            --account-type all --no-org-access \
            --regions "$REGIONS" \
            --output out/findings-$a.csv
done

# consolidate
{ head -1 out/findings-$(echo $ACCTS | awk '{print $1}').csv; \
  for f in out/findings-*.csv; do tail -n +2 "$f"; done; } > out/consolidated.csv
```

Useful single commands:
```bash
sraverify --list-checks                              # list all checks
sraverify --account-type application --regions us-east-1   # 63 checks, one account
sraverify --check SRA-GUARDDUTY-01 --regions us-east-1      # a single check
```

---

## 9. Understanding the output

| Status | Meaning | Action |
|---|---|---|
| **PASS** | Control satisfied | None |
| **FAIL** | Real misconfiguration | Remediate |
| **INSUFFICIENT_DATA** | Requires AWS Organizations / delegated-admin access not available here | **Not a finding** — exclude from remediation scoping |
| **ERROR** | Unexpected runtime error during the check | Investigate (permissions/region) |

The CLI summary prints all four counts. For Rapyder/remediation, scope only on **FAIL**; treat **INSUFFICIENT_DATA** as "out of scope in this deployment."

### How the tool decides
- A check needs org access iff `account_type != application` (all management/audit/log-archive).
- At runtime SRA Verify runs one `organizations:ListAccounts` probe:
  - denied/fails → org-dependent checks report `INSUFFICIENT_DATA` (no wasted denied calls);
  - succeeds (real org/delegated admin) → everything runs normally.
- Override with `--no-org-access` / `--assume-org-access`. (In the no-org template, `AllWithInsufficientData` mode passes `--no-org-access` for you.)

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Build fails at `--no-org-access: unrecognized arguments` | `SourceRepoUrl` points at upstream. Point it at your fork with the changes. |
| Every account shows `AssumeRole` errors | `SRAMemberRole` not deployed in those accounts, or `SRAVerifyAccountID` was set to the wrong scanning account. |
| Scan didn't start after deploy | Auto-start fires only on stack *create*. Run `aws codebuild start-build` manually. |
| All checks are `INSUFFICIENT_DATA` including application ones | You forced `--no-org-access` *and* something is off with selection — application checks never require org access; re-check `ScanMode`/flags. |
| Results bucket empty | Build still running, or it failed before `post_build`. Check CodeBuild logs. |
| Org-dependent checks show `FAIL` not `INSUFFICIENT_DATA` | Running upstream code, or `--assume-org-access` was set. Use the fork and `--no-org-access` / `ScanMode=AllWithInsufficientData`. |

---

## 11. Quick reference — end to end

```bash
# 1. Host the modified code
git push <your-remote> main

# 2. Member role into each target account (self-managed)
for acct in 111111111111 222222222222 333333333333 444444444444 555555555555; do
  aws cloudformation deploy --template-file 1-sraverify-member-roles.yaml \
    --stack-name sraverify-member-role \
    --parameter-overrides SRAVerifyAccountID=<SCANNING_ACCOUNT_ID> \
    --capabilities CAPABILITY_NAMED_IAM --profile acct-$acct
done

# 3. CodeBuild stack in the scanning account (auto-starts the scan)
aws cloudformation deploy --template-file 2-sraverify-codebuild-deploy-no-org.yaml \
  --stack-name sraverify \
  --parameter-overrides \
    TargetAccountIDs=111111111111,222222222222,333333333333,444444444444,555555555555 \
    SourceRepoUrl=https://github.com/CloudKeeper-Inc/sra-verify.git \
    ScanMode=AllWithInsufficientData \
    IncludeRegions=us-east-1,us-west-2 \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM --profile scanning-account

# 4. Monitor, then read results from the S3 bucket (contains 'bucketsraverifyfindings')
```
