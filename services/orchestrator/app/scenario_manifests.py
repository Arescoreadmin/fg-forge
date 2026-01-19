def learner_pod_yaml(scenario_id: str) -> str:
    return f"""
apiVersion: v1
kind: Pod
metadata:
  name: learner-{scenario_id}
  labels:
    app: learner
    scenario_id: "{scenario_id}"
spec:
  restartPolicy: Never
  containers:
    - name: learner
      image: alpine:3.20
      command: ["sh", "-c", "sleep 3600"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
"""
