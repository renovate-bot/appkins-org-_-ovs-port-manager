# Dependabot Auto-Approval Setup

This repository includes automated dependency management with Dependabot auto-approval and auto-merge functionality.

## How It Works

### 1. Dependabot Configuration (`.github/dependabot.yml`)
- **Go modules**: Weekly updates on Mondays at 4:00 AM UTC
- **Docker**: Weekly updates for Dockerfile base images
- **GitHub Actions**: Weekly updates for workflow actions
- Groups minor and patch updates to reduce PR noise
- Automatically adds appropriate labels and reviewers

### 2. Auto-Approval Workflow (`.github/workflows/dependabot-autoapprove.yml`)
Automatically approves Dependabot PRs for:
- ✅ **Patch updates** (e.g., 1.0.1 → 1.0.2)
- ✅ **Minor updates** (e.g., 1.0.0 → 1.1.0)
- ✅ **GitHub Actions updates**
- ❌ **Major updates** (require manual review)

### 3. Auto-Merge Workflow (`.github/workflows/dependabot-automerge.yml`)
Automatically merges approved PRs when:
- PR is approved (by auto-approval or manual review)
- All CI checks pass
- Update is considered safe (patch/minor/GitHub Actions)

### 4. Enhanced Workflow with CI Checks (`.github/workflows/dependabot-autoapprove-with-ci.yml`)
More comprehensive workflow that:
- Waits for CI tests to complete before approval
- Provides detailed comments on major updates
- Adds labels for different update types

## Safety Features

### Automatic Processing
- **Patch updates**: Auto-approved and auto-merged
- **Minor updates**: Auto-approved and auto-merged
- **GitHub Actions**: Auto-approved and auto-merged

### Manual Review Required
- **Major updates**: Commented with warning, labeled, requires manual approval
- **Failed CI**: No auto-merge until issues are resolved
- **Security updates**: Can be configured for immediate processing

### Labels
Dependabot PRs are automatically labeled:
- `dependencies`: All dependency updates
- `go`: Go module updates
- `docker`: Docker image updates
- `github-actions`: GitHub Actions updates
- `major-update`: Major version updates requiring review
- `needs-review`: Updates that need manual attention

## Repository Settings Required

To enable full functionality, ensure these repository settings:

### Branch Protection Rules
```yaml
main branch:
  - Require status checks to pass before merging
  - Require branches to be up to date before merging
  - Include administrators
  - Allow auto-merge
```

### Repository Settings
- Enable "Allow auto-merge"
- Enable "Automatically delete head branches"

## Workflows Overview

| Workflow | Purpose | Triggers |
|----------|---------|----------|
| `dependabot-autoapprove.yml` | Simple auto-approval | PR opened/updated |
| `dependabot-automerge.yml` | Auto-merge after CI | PR events, check completion |
| `dependabot-autoapprove-with-ci.yml` | Full CI integration | PR opened/updated |

## Manual Override

You can always:
- Manually review and approve any PR
- Close Dependabot PRs you don't want
- Modify auto-merge behavior by editing the workflows
- Disable auto-approval by removing/modifying the workflows

## Security Considerations

- Workflows use `pull_request_target` for Dependabot compatibility
- Minimal permissions granted (only what's needed)
- Major updates always require manual review
- CI must pass before auto-merge
- Repository admins can always override decisions
