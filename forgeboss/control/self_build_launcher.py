        if not path.is_file():return None
        try:value=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildLaunchError("CANDIDATE_EVIDENCE_INVALID","candidate evidence unreadable") from ex
        if not isinstance(value,dict) or value.get("schema")!=1:
            raise SelfBuildLaunchError("CANDIDATE_EVIDENCE_INVALID","candidate evidence schema invalid")
        digest=value.get("evidence_digest")
        unsigned={k:v for k,v in value.items() if k!="evidence_digest"}
        expected=hashlib.sha256(json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")).hexdigest()
        if digest!=expected:
            raise SelfBuildLaunchError("CANDIDATE_EVIDENCE_INVALID","candidate evidence digest mismatch")
        if value.get("task_id")!=item.get("task_id") or value.get("builder_id")!=item.get("builder_id"):
            raise SelfBuildLaunchError("CANDIDATE_EVIDENCE_INVALID","candidate evidence identity mismatch")
        return value

    def complete_worker(self,*,prepared_run:dict,launched_run:dict,builder_id:str)->dict:
        public=next((x for x in launched_run.get("workers") or [] if x.get("builder_id")==builder_id),None)
        item=self._prepared_item(prepared_run,builder_id)
        if public is None or item is None:
            raise SelfBuildLaunchError("WORKER_NOT_IN_RUN","worker not found in prepared/launch run")
        paths=self._paths(str(launched_run.get("run_id") or prepared_run.get("run_id") or ""),builder_id)
        if paths["handoff"].is_file():
            try:return json.loads(paths["handoff"].read_text(encoding="utf-8"))
            except Exception as ex:raise SelfBuildLaunchError("HANDOFF_EVIDENCE_INVALID","handoff evidence unreadable") from ex

        try:
            process=self.supervisor.complete(builder_id,int(public["generation"]),timeout=10.0)
        except SupervisorError as ex:
            detail=str(ex)
            try:
                result=load_result_file(public["result_file"],state_root=self.state_root)
                worker_error=result.get("error")
                if worker_error:
                    detail=f"{builder_id}: {detail}; worker error: {worker_error}"
                else:
                    detail=f"{builder_id}: {detail}; worker result completed={result.get('completed')} calls={result.get('calls')} cost_usd={result.get('cost_usd')}"
            except Exception:
                detail=f"{builder_id}: {detail}"
            raise SelfBuildLaunchError(ex.code,detail) from ex
        process_evidence=process.as_dict()
        docker_evidence=self.container_cleanup_fn(
            run_id=str(launched_run.get("run_id") or prepared_run.get("run_id") or ""),
            builder_id=builder_id,
        )
        process_evidence["dockerContainmentEmpty"]=docker_evidence.get("container_empty") is True
        candidate=self._load_candidate_evidence(paths["candidate"],item=item)
        if candidate is None:
            try:
                result=load_result_file(public["result_file"],state_root=self.state_root)
                candidate=self.freeze_fn(
                    item=item,public=public,result=result,process_evidence=process_evidence,
                    python_executable=self.python,
                )
            except SelfBuildFreezeError as ex:
                raise SelfBuildLaunchError(ex.code,str(ex)) from ex
            _atomic_json(paths["candidate"],candidate)

        response=self.client.record_self_build_handoff(
            run_id=str(launched_run.get("run_id") or prepared_run.get("run_id") or ""),
            task_id=item["task_id"],
            worker_run_id=item["authority"]["run_id"],
            owner_epoch=item["owner_epoch"],
            evidence=candidate,
        )
        handoff={
            "schema":1,
            "run_id":str(launched_run.get("run_id") or prepared_run.get("run_id") or ""),
            "builder_id":builder_id,
            "task_id":item["task_id"],
            "base_sha":candidate["base_sha"],
            "candidate_sha":candidate["candidate_sha"],
            "candidate_evidence":candidate,
            "process_evidence":process_evidence,
            "protected_handoff_receipt":response,
            "review_status":"FROZEN_AWAITING_INDEPENDENT_REVIEW",
        }
        _atomic_json(paths["handoff"],handoff)
        return handoff

    def review_candidate(self,*,prepared_run:dict,launched_run:dict,builder_id:str)->dict:
        item=self._prepared_item(prepared_run,builder_id)
        if item is None:raise SelfBuildLaunchError("WORKER_NOT_IN_RUN","worker not found in prepared run")
        run_id=str(launched_run.get("run_id") or prepared_run.get("run_id") or "")
        response=self.client.review_self_build_candidate(
            run_id=run_id,task_id=item["task_id"],worker_run_id=item["authority"]["run_id"],
            owner_epoch=item["owner_epoch"],
        )
        _atomic_json(self._paths(run_id,builder_id)["review"],response)
        return response

    def accept_reviewed_candidate(self,*,prepared_run:dict,launched_run:dict,builder_id:str)->dict:
        item=self._prepared_item(prepared_run,builder_id)
        if item is None:raise SelfBuildLaunchError("WORKER_NOT_IN_RUN","worker not found in prepared run")
        run_id=str(launched_run.get("run_id") or prepared_run.get("run_id") or "")
        response=self.client.accept_self_build_candidate(
            run_id=run_id,task_id=item["task_id"],worker_run_id=item["authority"]["run_id"],
            owner_epoch=item["owner_epoch"],
        )
        _atomic_json(self._paths(run_id,builder_id)["acceptance"],response)
        return response

    def finish_review_accept_compose(self,*,prepared_run:dict,launched_run:dict,
                                     builder_ids=("builder-a","builder-b2"),stop_requested=None,
                                     timeout:float=1200.0,poll_seconds:float=0.5)->dict:
        ids=tuple(builder_ids)
        if ids!=("builder-a","builder-b2"):
            raise SelfBuildLaunchError("FINISH_BUILDER_SET_INVALID","Finish Line 1 must finish exactly A + B2")
        if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or timeout<=0 or timeout>3600:
            raise SelfBuildLaunchError("FINISH_TIMEOUT_INVALID","finish timeout invalid")
        if isinstance(poll_seconds,bool) or not isinstance(poll_seconds,(int,float)) or poll_seconds<=0 or poll_seconds>10:
            raise SelfBuildLaunchError("FINISH_POLL_INVALID","finish poll interval invalid")
        checker=stop_requested if callable(stop_requested) else (lambda:False)