import os
import time
from typing import Dict, Optional

import yaml
from kubernetes import client, config, utils
from kubernetes.client.rest import ApiException


def load_kube() -> None:
    """Load kube config for dev or in-cluster."""
    if os.getenv("KUBERNETES_SERVICE_HOST"):
        config.load_incluster_config()
    else:
        config.load_kube_config(config_file=os.getenv("KUBECONFIG"))


class K8sAdapter:
    def __init__(self) -> None:
        load_kube()
        self.api_client = client.ApiClient()
        self.core = client.CoreV1Api()

    def create_namespace(self, name: str, labels: Optional[Dict[str, str]] = None) -> None:
        labels = labels or {}
        body = client.V1Namespace(metadata=client.V1ObjectMeta(name=name, labels=labels))
        try:
            self.core.create_namespace(body=body)
        except ApiException as e:
            if e.status == 409:
                return
            raise

    def delete_namespace(self, name: str) -> None:
        try:
            self.core.delete_namespace(name=name)
        except ApiException as e:
            if e.status == 404:
                return
            raise

    def apply_yaml(self, namespace: str, yaml_text: str) -> None:
        docs = list(yaml.safe_load_all(yaml_text))
        for d in docs:
            if not d:
                continue
            utils.create_from_dict(self.api_client, d, namespace=namespace)

    def wait_pods_ready(self, namespace: str, label_selector: str, timeout_seconds: int = 120) -> None:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            pods = self.core.list_namespaced_pod(
                namespace=namespace,
                label_selector=label_selector
            ).items

            if not pods:
                time.sleep(1)
                continue

            all_ready = True
            for p in pods:
                conditions = {c.type: c.status for c in (p.status.conditions or [])}
                if conditions.get("Ready") != "True":
                    all_ready = False
                    break

            if all_ready:
                return

            time.sleep(2)

        raise TimeoutError(f"Pods not ready: ns={namespace} selector={label_selector}")
