# Changelog

## v0.0.5
- switch back to v0.34.3 of k8s api by @pthum in #27
- bump version in charts for next release by @pthum in #28

## v0.0.4
- deps(k8s): update kubernetes packages to v0.34.3 (patch) by @renovate[bot] in #25
- Bugfix/fix handling by @pthum in #26
  - fix certificate handling and add a configuration option to configure naming
  - fix docker image build for other architectures than amd64
  - update dependencies

## v0.0.3
- Feature/enable image architectures by @pthum in #22
  - updated readme to match versions and provide correct chart repo url
  - added images for armv7 and arm64/v8 again
  - updated chart

## v0.0.2
- fix gha permissions by @pthum in #21

## v0.0.1
- initial release for this fork, includes all changes and features from previous versions released under a different name [see README](./README.md#history), especially:
  - Support for multiple credentialsSecretRefs [#7](https://gitlab.com/smueller18/cert-manager-webhook-inwx/-/issues/7)
  - Add CA certificates to Docker image
  - Add multi arch container images
  - Support INWX accounts protected by multi factor authentication
