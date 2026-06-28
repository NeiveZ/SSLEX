#!/usr/bin/env python3
# utils/session.py — Session manager for SSLEX

import uuid
from datetime import datetime


class Session:
    def __init__(self):
        self._id       = str(uuid.uuid4())[:8].upper()
        self._started  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._results: dict = {}
        self._reports: int  = 0
        self._scans:   int  = 0

    def add_results(self, module: str, results: list):
        if module not in self._results:
            self._results[module] = []
        self._results[module].extend(results)
        self._scans += 1

    def get_all_results(self) -> dict:
        return dict(self._results)

    def increment_reports(self):
        self._reports += 1

    def get_stats(self) -> dict:
        total = sum(len(v) for v in self._results.values())
        return {
            "id":      self._id,
            "started": self._started,
            "scans":   self._scans,
            "results": total,
            "reports": self._reports,
        }
