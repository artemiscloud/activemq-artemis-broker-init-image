# ActiveMQ Artemis broker init container image

Init container image that configures artemis broker instances

## License

See [LICENSE](LICENSE) file.

## How to build

```$shell
podman build --no-cache activemq-artemis-broker-init:latest .
```

## Repository

The ActiveMQ Artemis broker init container images are pushed to <https://quay.io/repository/artemiscloud/activemq-artemis-broker-init>

## Tags

The ActiveMQ Artemis broker init container images have release tags and special tags.

The image release tags point to images built from the sources of the releated release tags,
i.e. the `1.0.0` image release tag points to the image built from
the sources of the [v1.0.0](https://github.com/artemiscloud/activemq-artemis-broker-init-image/tree/v1.0.0) release tag

The image special tags are:

- `artemis.ARTEMIS_VERSION` - points to the image built from the sources of a release tag and a specific artemis version. ie: `artemis.2.31.2`

- `latest` - points to the image built from the sources of the latest release tag.

- `dev.DATE.COMMIT_ID` - points to the image built from the sources of the main branch on specific date and commit id, it should be used only for development purposes. ie: `dev.20231110.5cea3ed`. It expires in 3 months

- `dev.latest` - points to the image built from the latest sources of the main branch, it should be used only for development purposes and it is regenerated on each commit on main branch.

- `snapshot` - points to the image built from the latest sources of the main branch and contains the snapshot version of ActiveMQ Artemis

NOTE: Some tags are tied together at some point. We may have the `latest` tag been equal the tag for version `1.0.23` and also equal the tag for `artemis.2.31.2`. The same applies to `dev.latest` tag which will the equal the latest commit tag, ie: `dev.20231110.5cea3ed`
