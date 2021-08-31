# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
ENTRYPOINT ["/manager"]
WORKDIR /
USER nonroot:nonroot
COPY manager /
