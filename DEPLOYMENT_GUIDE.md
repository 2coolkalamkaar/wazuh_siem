# Wazuh SIEM — Step-by-Step Deployment Guide

**Estimated Total Time:** ~25 minutes  
**Prerequisites:** A running Kubernetes cluster (AKS, EKS, GKE, or self-managed) with `kubectl` access and at least 8GB RAM available across nodes.

---

## Quick Overview

You will perform 4 phases:

| Phase | What | Time |
|---|---|---|
| **Phase 1** | Deploy Wazuh Platform (Indexer + Manager + Dashboard) | ~10 min |
| **Phase 2** | Deploy Fluent Bit Log Collector (DaemonSet) | ~3 min |
| **Phase 3** | Deploy Custom Decoders & Rules | ~5 min |
| **Phase 4** | Verify the Pipeline & Access Dashboard | ~5 min |

---

## Phase 1: Deploy the Wazuh Platform

This deploys the Wazuh Manager (Master + Worker), Wazuh Indexer (OpenSearch), and Wazuh Dashboard.

### Step 1.1 — Clone this repository

```bash
git clone https://github.com/2coolkalamkaar/wazuh_siem.git
cd wazuh_siem
```

### Step 1.2 — Generate fresh TLS certificates

> ⚠️ **Do NOT use the certificates already in the repo.** Generate fresh ones for your environment.

```bash
cd wazuh-kubernetes/wazuh/certs/indexer_cluster
bash generate_certs.sh
cd ../dashboard_http
bash generate_certs.sh
cd ../../../..
```

### Step 1.3 — Configure the Storage Class

Edit the storage class to match your cloud provider:

```bash
vi wazuh-kubernetes/wazuh/base/storage-class.yaml
```

**For AKS (Azure):**
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-storage
provisioner: disk.csi.azure.com
parameters:
  skuName: Premium_LRS
reclaimPolicy: Retain
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
```

**For EKS (AWS):**
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-storage
provisioner: ebs.csi.aws.com
parameters:
  type: gp3
reclaimPolicy: Retain
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
```

**For GKE (Google Cloud):**
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-storage
provisioner: pd.csi.storage.gke.io
parameters:
  type: pd-ssd
reclaimPolicy: Retain
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
```

### Step 1.4 — Enable Syslog on the Wazuh Worker

Fluent Bit sends logs to Wazuh via Syslog on port 514. By default, the Wazuh Worker config does not have a Syslog listener. You must add it.

Edit the worker configuration:

```bash
vi wazuh-kubernetes/wazuh/wazuh_managers/wazuh_conf/worker.conf
```

Add the following block **inside the `<ossec_config>` section**, right after the existing `<remote>` block (around line 41):

```xml
  <!-- Syslog input from Fluent Bit -->
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>tcp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
  </remote>
```

### Step 1.5 — Expose Syslog Port 514 on the Workers Service

The default Workers Service only exposes port 1514 (agent communication). Fluent Bit needs port 514.

Edit the workers service:

```bash
vi wazuh-kubernetes/wazuh/wazuh_managers/wazuh-workers-svc.yaml
```

Add port 514 to the `ports` section:

```yaml
spec:
  type: ClusterIP    # Changed from LoadBalancer — no need to expose externally
  selector:
    app: wazuh-manager
    node-type: worker
  ports:
    - name: agents-events
      port: 1514
      targetPort: 1514
    - name: syslog
      port: 514
      targetPort: 514
```

### Step 1.6 — Deploy Wazuh with Kustomize

```bash
kubectl apply -k wazuh-kubernetes/wazuh/
```

### Step 1.7 — Wait for all pods to be Running

```bash
kubectl get pods -n wazuh -w
```

Wait until you see all pods in `Running` status:

```
NAME                              READY   STATUS    AGE
wazuh-indexer-0                   1/1     Running   2m
wazuh-manager-master-0            1/1     Running   2m
wazuh-manager-worker-0            1/1     Running   2m
wazuh-dashboard-xxxxxxxxx-xxxxx   1/1     Running   2m
```

> **Troubleshooting:** If pods are stuck in `Pending`, check if the StorageClass is correct with `kubectl describe pvc -n wazuh`. If `CrashLoopBackOff`, check logs with `kubectl logs -n wazuh <pod-name>`.

---

## Phase 2: Deploy Fluent Bit Log Collector

Fluent Bit runs as a DaemonSet on every node, tailing all container logs and forwarding them to Wazuh.

### Step 2.1 — Create the namespace, RBAC, and ServiceAccount

```bash
kubectl apply -f fluent-bit-wazuh-v2/fluent-bit-rbac.yaml
```

This creates:
- Namespace: `wazuh-log-collector`
- ServiceAccount: `fluent-bit`
- ClusterRole + ClusterRoleBinding: Allows Fluent Bit to read pod/namespace metadata

### Step 2.2 — Deploy the Fluent Bit ConfigMap

```bash
kubectl apply -f fluent-bit-wazuh-v2/fluent-bit-config.yaml
```

This configures:
- **INPUT (tail):** Tails `/var/log/containers/*.log` — captures ALL container logs
- **INPUT (systemd):** Captures `kubelet` and `containerd` node-level logs
- **FILTER (kubernetes):** Enriches each log with pod name, namespace, container name
- **OUTPUT (syslog):** Forwards to `wazuh-workers.wazuh.svc.cluster.local:514` via TCP

### Step 2.3 — Deploy the Fluent Bit DaemonSet

```bash
kubectl apply -f fluent-bit-wazuh-v2/fluent-bit-daemonset.yaml
```

### Step 2.4 — Verify Fluent Bit is running on all nodes

```bash
kubectl get pods -n wazuh-log-collector -o wide
```

You should see one Fluent Bit pod per node:

```
NAME               READY   STATUS    NODE
fluent-bit-abc12   1/1     Running   node-1
fluent-bit-def34   1/1     Running   node-2
```

Check logs to confirm it is actively tailing:

```bash
kubectl logs -n wazuh-log-collector -l app=fluent-bit --tail 20
```

You should see `inotify_fs_add` entries — this means Fluent Bit is actively watching container log files.

---

## Phase 3: Deploy Custom Decoders & Rules

By default, Wazuh does not understand the log formats coming from Teleport, your applications, or Kubernetes klog. We need to deploy custom decoders and rules to both Wazuh Manager pods.

### Step 3.1 — Copy decoder files to both Manager pods

```bash
# Copy to Master
kubectl cp local_decoder.xml wazuh/wazuh-manager-master-0:/var/ossec/etc/decoders/local_decoder.xml

# Copy to Worker
kubectl cp local_decoder.xml wazuh/wazuh-manager-worker-0:/var/ossec/etc/decoders/local_decoder.xml
```

### Step 3.2 — Copy rule files to both Manager pods

```bash
# Teleport Rules
kubectl cp teleport_rules.xml wazuh/wazuh-manager-master-0:/var/ossec/etc/rules/teleport_rules.xml
kubectl cp teleport_rules.xml wazuh/wazuh-manager-worker-0:/var/ossec/etc/rules/teleport_rules.xml

# Kubernetes & Application Rules
kubectl cp kubernetes_rules.xml wazuh/wazuh-manager-master-0:/var/ossec/etc/rules/kubernetes_rules.xml
kubectl cp kubernetes_rules.xml wazuh/wazuh-manager-worker-0:/var/ossec/etc/rules/kubernetes_rules.xml
```

### Step 3.3 — Validate the configuration (no syntax errors)

```bash
kubectl exec -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/wazuh-logtest -t
```

If the output ends with `Configuration validation completed successfully`, you are good. If there is an XML error, fix the offending file and re-copy.

### Step 3.4 — Restart Wazuh on both pods to load the new decoders/rules

```bash
kubectl exec -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/wazuh-control restart
kubectl exec -n wazuh wazuh-manager-worker-0 -- /var/ossec/bin/wazuh-control restart
```

Wait ~15 seconds for the engine to fully restart.

---

## Phase 4: Verify the Pipeline & Access Dashboard

### Step 4.1 — Generate a test log to confirm end-to-end flow

Deploy a temporary pod that outputs a fake application error:

```bash
kubectl run test-siem --image=busybox --restart=Never -- sh -c \
  'echo "{\"level\":\"error\",\"message\":\"SIEM pipeline test - if you see this alert, the pipeline is working!\"}" && sleep 5'
```

### Step 4.2 — Check if Wazuh received and alerted on the test log

Wait ~30 seconds for the log to flow through the pipeline, then:

```bash
kubectl exec -n wazuh wazuh-manager-worker-0 -- grep "SIEM pipeline test" /var/ossec/logs/alerts/alerts.json | tail -1
```

**If you see a JSON alert containing your test message and `rule.id: 100301`, the entire pipeline is working!**

### Step 4.3 — Clean up the test pod

```bash
kubectl delete pod test-siem --ignore-not-found
```

### Step 4.4 — Access the Wazuh Dashboard

Port-forward the Dashboard to your local machine:

```bash
kubectl port-forward -n wazuh svc/dashboard 5601:5601
```

Open your browser and navigate to:

```
https://localhost:5601
```

**Default Credentials:**
- Username: `admin`
- Password: Check the secret: `kubectl get secret -n wazuh wazuh-dashboard-cred -o jsonpath='{.data.password}' | base64 -d`

> **For production access:** Instead of port-forwarding, create an Ingress resource or change the Dashboard Service to `type: LoadBalancer` to expose it on a public/private IP.

### Step 4.5 — Navigate to Security Events

1. Click the **☰ hamburger menu** (top-left)
2. Go to **Modules** → **Security Events**
3. Or go to **Discover** and filter by:
   - `rule.groups: "app"` — to see application errors
   - `rule.groups: "teleport"` — to see Teleport audit events
   - `rule.groups: "kubernetes"` — to see K8s infrastructure events
   - `rule.id: "100301"` — to find your specific test alert

---

## Summary of Commands (Quick Reference)

```bash
# ---- Phase 1: Wazuh Platform ----
git clone https://github.com/2coolkalamkaar/wazuh_siem.git && cd wazuh_siem
# (Edit storage-class.yaml, worker.conf, workers-svc.yaml as described above)
kubectl apply -k wazuh-kubernetes/wazuh/
kubectl get pods -n wazuh -w

# ---- Phase 2: Fluent Bit ----
kubectl apply -f fluent-bit-wazuh-v2/fluent-bit-rbac.yaml
kubectl apply -f fluent-bit-wazuh-v2/fluent-bit-config.yaml
kubectl apply -f fluent-bit-wazuh-v2/fluent-bit-daemonset.yaml
kubectl get pods -n wazuh-log-collector

# ---- Phase 3: Decoders & Rules ----
kubectl cp local_decoder.xml wazuh/wazuh-manager-master-0:/var/ossec/etc/decoders/local_decoder.xml
kubectl cp local_decoder.xml wazuh/wazuh-manager-worker-0:/var/ossec/etc/decoders/local_decoder.xml
kubectl cp teleport_rules.xml wazuh/wazuh-manager-master-0:/var/ossec/etc/rules/teleport_rules.xml
kubectl cp teleport_rules.xml wazuh/wazuh-manager-worker-0:/var/ossec/etc/rules/teleport_rules.xml
kubectl cp kubernetes_rules.xml wazuh/wazuh-manager-master-0:/var/ossec/etc/rules/kubernetes_rules.xml
kubectl cp kubernetes_rules.xml wazuh/wazuh-manager-worker-0:/var/ossec/etc/rules/kubernetes_rules.xml
kubectl exec -n wazuh wazuh-manager-master-0 -- /var/ossec/bin/wazuh-control restart
kubectl exec -n wazuh wazuh-manager-worker-0 -- /var/ossec/bin/wazuh-control restart

# ---- Phase 4: Verify ----
kubectl run test-siem --image=busybox --restart=Never -- sh -c 'echo "{\"level\":\"error\",\"message\":\"SIEM test\"}" && sleep 5'
sleep 30
kubectl exec -n wazuh wazuh-manager-worker-0 -- grep "SIEM test" /var/ossec/logs/alerts/alerts.json | tail -1
kubectl port-forward -n wazuh svc/dashboard 5601:5601
# Open https://localhost:5601
```
