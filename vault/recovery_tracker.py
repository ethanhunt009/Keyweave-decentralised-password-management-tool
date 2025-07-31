import time
import json
import os
import config

class RecoveryTracker:
    def __init__(self):
        self.log_file = os.path.join(config.Config.DATA_DIR, "recovery_logs.json")
        self.logs = self._load_logs()
    
    def _load_logs(self):
        if os.path.exists(self.log_file):
            with open(self.log_file, "r") as f:
                return json.load(f)
        return {}
    
    def _save_logs(self):
        with open(self.log_file, "w") as f:
            json.dump(self.logs, f, indent=2)
    
    def log_recovery_start(self, recovery_id):
        self.logs[recovery_id] = {
            "start_time": time.time(),
            "status": "initiated",
            "guardian_responses": {},
            "events": [{"time": time.time(), "event": "recovery_started"}]
        }
        self._save_logs()
    
    def log_guardian_response(self, recovery_id, guardian_url, success):
        if recovery_id in self.logs:
            log = self.logs[recovery_id]
            log["guardian_responses"][guardian_url] = {
                "time": time.time(),
                "success": success
            }
            event = "guardian_success" if success else "guardian_failure"
            log["events"].append({
                "time": time.time(),
                "event": event,
                "guardian": guardian_url
            })
            self._save_logs()
    
    def log_recovery_success(self, recovery_id):
        if recovery_id in self.logs:
            self.logs[recovery_id]["status"] = "success"
            self.logs[recovery_id]["end_time"] = time.time()
            self.logs[recovery_id]["events"].append({
                "time": time.time(),
                "event": "recovery_success"
            })
            self._save_logs()
    
    def log_recovery_failure(self, recovery_id):
        if recovery_id in self.logs:
            self.logs[recovery_id]["status"] = "failed"
            self.logs[recovery_id]["end_time"] = time.time()
            self.logs[recovery_id]["events"].append({
                "time": time.time(),
                "event": "recovery_failed"
            })
            self._save_logs()
    
    def get_log(self, recovery_id):
        return self.logs.get(recovery_id)
    
    def get_recovery(self, recovery_id):
        return self.logs.get(recovery_id)