param(
  [int]$PullRequest,
  [string]$ResultPath,
  [switch]$ReviewOnly,
  [switch]$UseCache,
  [ValidateSet('main','child')][string]$ReviewMode='main',
  [string]$ExpectedBaseRef='',
  [string]$ExpectedBaseSha='',
  [int]$ParentPullRequest=0
)
$ErrorActionPreference='Stop'
if($PullRequest-ne525){throw "PullRequest bind failed: $PullRequest"}
if($ReviewMode-ne'child'){throw "ReviewMode bind failed: $ReviewMode"}
if($ExpectedBaseRef-ne'beta/issue-155-travis-intake-orchestration'){throw "ExpectedBaseRef bind failed: $ExpectedBaseRef"}
if($ExpectedBaseSha-ne'0acc7149044fdc6403e8d8d781d9dfcca63bfb1b'){throw "ExpectedBaseSha bind failed: $ExpectedBaseSha"}
if($ParentPullRequest-ne168){throw "ParentPullRequest bind failed: $ParentPullRequest"}
if(-not$ReviewOnly-or-not$UseCache){throw 'Switch binding failed'}
Write-Host 'CHILD REVIEW ARGUMENT BINDING SELFTEST: PASS'
