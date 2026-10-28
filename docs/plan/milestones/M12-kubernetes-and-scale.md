# M12 · Kubernetes and scale

- Phase: 4 · Scale
- Depends on: M11
- Ships: `v1.1.0`
- Read first: `docs/architecture/overview.md` (topologies), `docs/operations/deployment.md`

## Goal

Run Sherlock comfortably in Kubernetes and at higher traffic, and make multi-node OSS deployments easy via GitOps.

## Tasks

- [ ] **M12-T1** Helm chart `deploy/helm/sherlock`: Deployment/StatefulSet option, Service (LoadBalancer/NodePort), PVC for data, Secret for node key, ConfigMap-driven config (`sherlock config apply` on start), probes, PodSecurity restricted, NetworkPolicy example, ServiceMonitor.
- [ ] **M12-T2** Config-as-code: `sherlock config apply --prune` semantics, drift detection (`sherlock config diff`), documented GitOps workflow with Argo CD/Flux.
- [ ] **M12-T3** Performance pass: profile with pprof under k6 at 2× NFR-2, optimise hot paths, re-baseline benchmarks; publish results in `docs/plan/benchmarks.md`.
- [ ] **M12-T4** Grafana dashboard JSON for the Prometheus metrics.
- [ ] **M12-T5** Postgres partitioning for events (daily partitions, partition drop for retention).
- [ ] **M12-T6** Docs: Kubernetes guide, multi-node OSS guide (independent nodes behind a load balancer, shared config via Git), sizing guide updated from measurements.

## Acceptance criteria

1. `helm install` on kind and on a managed Kubernetes protects a sample app; chart passes `helm lint` and `kubeconform`.
2. Two independent nodes converge to the same config from Git within 1 minute of a commit.
3. Updated benchmark numbers published; no NFR regressions.
