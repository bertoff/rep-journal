param(
  [string]$Message = "",
  [switch]$SkipPull
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Message)) {
  $Message = "publish: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
}

$insideRepo = (git rev-parse --is-inside-work-tree 2>$null)
if ($LASTEXITCODE -ne 0 -or $insideRepo.Trim() -ne "true") {
  throw "Not inside a git repository."
}

$branch = (git branch --show-current).Trim()
if ([string]::IsNullOrWhiteSpace($branch)) {
  throw "Could not determine current branch."
}

if (-not $SkipPull) {
  Write-Host "Pulling latest changes from origin/$branch..."
  git pull --rebase origin $branch
  if ($LASTEXITCODE -ne 0) {
    throw "git pull --rebase failed. Resolve issues and try again."
  }
}

$status = git status --porcelain
if (-not [string]::IsNullOrWhiteSpace($status)) {
  Write-Host "Staging changes..."
  git add -A

  Write-Host "Creating commit..."
  git commit -m $Message
  if ($LASTEXITCODE -ne 0) {
    throw "git commit failed."
  }
} else {
  Write-Host "No local changes to commit."
}

Write-Host "Pushing to origin/$branch..."
git push origin $branch
if ($LASTEXITCODE -ne 0) {
  throw "git push failed."
}

Write-Host "Publish complete on origin/$branch."
