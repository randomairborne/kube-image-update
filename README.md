# kube-image-update

## Totally broken, archived in favor of service accounts and kubectl 

## About

I have been learning kubernetes lately and I found
that automatically updating containers without
retagging them to be unnecessarily complex. I just
want to fire a GitHub webhook and have it taken care
of. Thus, I have written this simple container which 
interacts with the Kubernetes API to force a rolling 
restart, which will take a deployment using the 
`latest` tag or with the `imagePullPolicy` set to 
`Always` and load the currently available image.

Equivalent to `kubectl rollout restart`, but using 
that in CI is incredibly ugly (and insecure!)

## Configuration

The container takes one environment variable,
`TOKEN_SECRET_NAMESPACE`, which can change the
namespace where the `kube-restart-tokens` secret
is stored.

Speaking of `kube-restart-tokens`, it is a simple
secret map. However, to allow restarting containers
in any namespace, you must use a `.` between the
namespace and the deployment name. 

GitHub webhooks send a HMAC-SHA256 secret if configured.
Your webhook MUST be configured with a secret for this
application to work.

For example, your secret definition could look like this:

### GENERATE YOUR SECRETS IN A SECURELY RANDOM WAY, AND MAKE THEM AT LEAST 64 CHARACTERS

```yaml

apiVersion: v1
kind: Secret
metadata:
  name: kube-restart-tokens
data:
  core.userauth: c2VjcmV0Cg== # randomly generated
  default.kubeimageupdate: c2Vrcml0Cg== # also randomly generated
```

Make sure when you run `base64`, there's no newline!

You can then set your GitHub webhooks to a path like
`https://kube-hooks.example.com/core/userauth` to select
the userauth deployment on the core namespace with the unencoded
secret and whatever GitHub events you wish to trigger a restart.

## Install

```bash
kubectl create secret generic kube-restart-tokens --from-literal=<namespace>.<deployment>=<random token>
kubectl apply -f https://raw.githubusercontent.com/randomairborne/kube-image-update/main/kube-image-update.yml
```

