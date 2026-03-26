"""
v1_api.py — V1 REST API wrapper using credential store.
Pulls container security data: vulns, clusters, image occurrences, events.
"""

import os
import sys
import json
import requests
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/.claude/skills/credential-manager"))
from claude_cred import resolve as cred_resolve


class V1API:
    def __init__(self, region="us-east-1", api_key_name="v1-api/V1_API_KEY"):
        self.key = cred_resolve(api_key_name)
        if not self.key:
            raise RuntimeError(f"No {api_key_name} in credential store")
        self.key = self.key.strip()
        bases = {
            "us-east-1": "https://api.xdr.trendmicro.com",
            "eu-central-1": "https://api.eu.xdr.trendmicro.com",
            "ap-southeast-1": "https://api.sg.xdr.trendmicro.com",
            "ap-northeast-1": "https://api.jp.xdr.trendmicro.com",
            "ap-southeast-2": "https://api.au.xdr.trendmicro.com",
        }
        self.base = bases.get(region, bases["us-east-1"])
        self.h = {"Authorization": f"Bearer {self.key}"}

    def _pages(self, path, params=None, max_pages=20):
        items, url = [], f"{self.base}{path}"
        for _ in range(max_pages):
            r = requests.get(url, headers=self.h, params=params, timeout=30)
            r.raise_for_status()
            d = r.json()
            items.extend(d.get("items", []))
            nxt = d.get("nextLink")
            if not nxt:
                break
            url, params = nxt, None
        return items

    def clusters(self):
        return self._pages("/v3.0/containerSecurity/kubernetesClusters")

    def vulns(self, limit=200):
        return self._pages("/v3.0/containerSecurity/vulnerabilities", {"limit": limit})

    def image_occurrences(self):
        return self._pages("/v3.0/containerSecurity/kubernetesImageOccurrences")

    def eval_events(self):
        return self._pages("/v3.0/containerSecurity/kubernetesEvaluationEventLogs")

    def sensor_events(self):
        return self._pages("/v3.0/containerSecurity/kubernetesSensorEventLogs")

    def audit_events(self):
        return self._pages("/v3.0/containerSecurity/kubernetesAuditEventLogs")

    def ecs_clusters(self):
        return self._pages("/v3.0/containerSecurity/amazonEcsClusters")

    def pull_all(self):
        """Pull all container security data in one call."""
        data = {
            "clusters": self.clusters(),
            "vulns": self.vulns(),
            "occurrences": self.image_occurrences(),
            "eval_events": self.eval_events(),
            "sensor_events": self.sensor_events(),
            "audit_events": self.audit_events(),
        }
        return data


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", default="v1-data.json")
    args = parser.parse_args()

    api = V1API(args.region)
    data = api.pull_all()
    with open(args.output, "w") as f:
        json.dump(data, f, indent=2)

    for k, v in data.items():
        print(f"  {k}: {len(v)}")
    print(f"Saved to {args.output}")
