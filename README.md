# k8s-metadata-proxy

This repo contains a simple proxy for serving concealed metadata to container
workloads running in kubernetes/kubernetes on a GCE VM.

## Performance

`metadata-proxy` has been benchmarked to serve 100 concurrent requests
approximately indefinitely, given 15MiB memory and 30m cpu.

```
TODO
```
