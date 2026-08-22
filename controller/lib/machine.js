'use strict';
const ALLOWED = {
  BOOT:['PREFLIGHT','RECOVERY','SAFE_STOP'],
  PREFLIGHT:['SYNC','BLOCKED','SAFE_STOP'],
  SYNC:['READ_CONTROL','BLOCKED','SAFE_STOP'],
  READ_CONTROL:['INSPECT','BLOCKED','SAFE_STOP'],
  INSPECT:['PLAN','BLOCKED','SAFE_STOP'],
  PLAN:['QUEUE','NEEDS_OWNER','SAFE_STOP'],
  QUEUE:['EXECUTE','COMPLETE','SAFE_STOP'],
  EXECUTE:['VALIDATE','BLOCKED','RETRY_WAIT','NEEDS_OWNER','SAFE_STOP'],
  VALIDATE:['REVIEW','REPAIR_IF_REQUIRED','NEEDS_OWNER','SAFE_STOP'],
  REVIEW:['COMMIT','REPAIR_IF_REQUIRED','NEEDS_OWNER','SAFE_STOP'],
  REPAIR_IF_REQUIRED:['REVALIDATE','NEEDS_OWNER','SAFE_STOP'],
  REVALIDATE:['REVIEW','NEEDS_OWNER','SAFE_STOP'],
  COMMIT:['PUBLISH','NEEDS_OWNER','SAFE_STOP'],
  PUBLISH:['UPDATE_CONTROL','NEEDS_OWNER','SAFE_STOP'],
  UPDATE_CONTROL:['CHECK_NEXT_WORK','NEEDS_OWNER','SAFE_STOP'],
  CHECK_NEXT_WORK:['PLAN','COMPLETE','SAFE_STOP'],
  BLOCKED:['RECOVERY','SAFE_STOP','NEEDS_OWNER'],
  RETRY_WAIT:['EXECUTE','SAFE_STOP'],
  NEEDS_OWNER:['RECOVERY','SAFE_STOP'],
  RECOVERY:['PREFLIGHT','INSPECT','SAFE_STOP'],
  COMPLETE:[],
  SAFE_STOP:[]
};
function transition(runState, to, reason='') {
  const from = runState.state;
  const allowed = ALLOWED[from] || [];
  if (!allowed.includes(to)) {
    const e = new Error(`Invalid controller transition ${from} -> ${to}`);
    e.code = 'INVALID_TRANSITION';
    throw e;
  }
  runState.history.push({at:new Date().toISOString(),from,to,reason});
  runState.state = to;
  runState.updated_at = new Date().toISOString();
}
module.exports = { ALLOWED, transition };
