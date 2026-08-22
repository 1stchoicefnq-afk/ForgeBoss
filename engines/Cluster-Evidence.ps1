param(
  [string[]]$Inputs=@(),
  [string]$InputListPath='',
  [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'State.psm1') -Force

function Get-OptionalProperty([object]$Object,[string]$Name){
  if($null-eq$Object){return $null}
  $prop=$Object.PSObject.Properties[$Name]
  if($null-eq$prop){return $null}
  return $prop.Value
}

function Add-RunSet([System.Collections.Generic.List[object]]$Sets,[object]$Value){
  if($null-eq$Value){return}
  foreach($entry in @($Value)){
    if($null-ne$entry){[void]$Sets.Add($entry)}
  }
}

if($InputListPath){
  if(-not(Test-Path -LiteralPath $InputListPath)){throw "Evidence input manifest missing: $InputListPath"}
  try{
    $manifest=Get-Content -LiteralPath $InputListPath -Raw|ConvertFrom-Json
  }catch{
    throw "Evidence input manifest is invalid JSON: $InputListPath :: $($_.Exception.Message)"
  }
  $manifestInputs=Get-OptionalProperty $manifest 'inputs'
  if($null-eq$manifestInputs){throw "Evidence input manifest missing inputs array: $InputListPath"}
  $Inputs=@($manifestInputs|ForEach-Object{"$_"}|Where-Object{$_})
}

$items=@()
$skippedInputs=@()
foreach($path in $Inputs){
  if(-not(Test-Path -LiteralPath $path)){
    $skippedInputs+=@([ordered]@{path=$path;reason='missing'})
    continue
  }
  try{
    $raw=Get-Content -LiteralPath $path -Raw
    $json=$raw|ConvertFrom-Json
  }catch{
    $skippedInputs+=@([ordered]@{path=$path;reason='invalid-json';detail=$_.Exception.Message})
    continue
  }
  $items+=@([ordered]@{path=$path;sha256=(Get-TextSha256 $raw);json=$json})
}

$failures=@()
$shapeInventory=@()

foreach($item in $items){
  $sets=[System.Collections.Generic.List[object]]::new()
  $shape=[System.Collections.Generic.List[string]]::new()

  $results=Get-OptionalProperty $item.json 'results'
  if($null-ne$results){
    Add-RunSet $sets $results
    [void]$shape.Add('results')
  }

  $acceptance=Get-OptionalProperty $item.json 'acceptance'
  if($null-ne$acceptance){
    $runs=Get-OptionalProperty $acceptance 'runs'
    if($null-ne$runs){
      Add-RunSet $sets $runs
      [void]$shape.Add('acceptance.runs')
    }
    $rounds=Get-OptionalProperty $acceptance 'validation_rounds'
    if($null-ne$rounds){
      foreach($round in @($rounds)){
        $roundRuns=Get-OptionalProperty $round 'runs'
        if($null-ne$roundRuns){Add-RunSet $sets $roundRuns}
      }
      [void]$shape.Add('acceptance.validation_rounds.runs')
    }
  }

  # Rat Review v0.1+ may expose clean acceptance under validation_rounds directly.
  $validationRounds=Get-OptionalProperty $item.json 'validation_rounds'
  if($null-ne$validationRounds){
    foreach($round in @($validationRounds)){
      $roundRuns=Get-OptionalProperty $round 'runs'
      if($null-ne$roundRuns){Add-RunSet $sets $roundRuns}
    }
    [void]$shape.Add('validation_rounds.runs')
  }

  # Some historical reports place the run list under acceptance_runs/runs.
  $acceptanceRuns=Get-OptionalProperty $item.json 'acceptance_runs'
  if($null-ne$acceptanceRuns){
    Add-RunSet $sets $acceptanceRuns
    [void]$shape.Add('acceptance_runs')
  }

  $rootRuns=Get-OptionalProperty $item.json 'runs'
  if($null-ne$rootRuns){
    Add-RunSet $sets $rootRuns
    [void]$shape.Add('runs')
  }

  $shapeInventory+=@([ordered]@{
    path=$item.path
    recognized=@($shape)
    extracted_run_count=$sets.Count
  })

  foreach($run in $sets){
    if($null-eq$run){continue}

    $exitCode=Get-OptionalProperty $run 'exit_code'
    if($null-eq$exitCode){
      # Not every object in historical evidence is an executable test result.
      continue
    }
    if("$exitCode"-eq'0'){continue}

    $name=Get-OptionalProperty $run 'name'
    if([string]::IsNullOrWhiteSpace("$name")){$name='unnamed-run'}

    $failureLines=Get-OptionalProperty $run 'failure_lines'
    $lines=@()
    if($null-ne$failureLines){$lines=@($failureLines|Where-Object{$_})}

    if($lines.Count-eq0){
      foreach($field in @('stderr','stdout','error','detail','reason')){
        $value=Get-OptionalProperty $run $field
        if(-not[string]::IsNullOrWhiteSpace("$value")){
          $lines+=@("$value")
          break
        }
      }
    }

    $signature=(($lines|Select-Object -First 8)-join'|')
    if(-not$signature){$signature="$name`:exit=$exitCode"}

    $failures+=@([ordered]@{
      source=$item.path
      name="$name"
      exit_code="$exitCode"
      signature=$signature
    })
  }
}

$groups=@{}
foreach($failure in $failures){
  $key=Get-TextSha256 $failure.signature
  if(-not$groups.ContainsKey($key)){$groups[$key]=@()}
  $groups[$key]+=$failure
}

$clusters=@()
foreach($key in $groups.Keys){
  $members=@($groups[$key])
  $clusters+=@([ordered]@{
    id=$key
    count=$members.Count
    names=@($members.name|Select-Object -Unique)
    sources=@($members.source|Select-Object -Unique)
    signatures=@($members.signature|Select-Object -Unique)
  })
}

$out=[ordered]@{
  schema=2
  generated_at=[DateTimeOffset]::UtcNow.ToString('o')
  requested_input_count=$Inputs.Count
  input_count=$items.Count
  skipped_input_count=$skippedInputs.Count
  skipped_inputs=@($skippedInputs)
  failure_count=$failures.Count
  cluster_count=$clusters.Count
  shape_inventory=@($shapeInventory)
  clusters=@($clusters|Sort-Object count -Descending)
}
Write-JsonAtomic $Output $out 60
$out
