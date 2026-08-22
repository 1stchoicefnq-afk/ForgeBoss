SITEBOSS AUTOPILOT v0.9-control-integration

Normal free/read-only test:
  SITEBOSS-AUTOPILOT.cmd

Flow:
  doctor
  -> live GitHub App read of root PR + repair PR
  -> verify repair base == root head
  -> exact Git mirror fetch
  -> dependency-expanded repair scope
  -> bounded packet
  -> persist + stop

Explicit paid local repair/review test:
  AUTOPILOT-REPAIR-PAID.cmd

The paid path uses the controller-generated exact-head ScopeManifest.
Repair Rat refuses a scope manifest if its PR/head does not match the checkout.
Independent Rat Review is forced into -NoPublish mode.

v0.9 CANNOT publish through the controller:
  push OFF
  draft PR publication OFF
  merge OFF
  deploy OFF

This checkpoint is specifically intended to solve the narrow-scope failure seen after the working v0.4.7 cycle.
