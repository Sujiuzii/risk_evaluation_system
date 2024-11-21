# Use the official Golang image to create a build artifact.
# This is based on Debian and sets the GOPATH to /go.
FROM golang:1.22 as builder

# Copy the local package files to the container's workspace.
ADD . /go/src/myapp
WORKDIR /go/src/myapp

# Building the Go app
RUN go get -d -v ./...
RUN go install -v ./...

# Use a Docker multi-stage build to create a lean production image.
# https://docs.docker.com/develop/develop-images/multistage-build/
FROM debian:buster-slim

# Copy the executable to the production image from the builder stage.
COPY --from=builder /go/bin/myapp /usr/local/bin/myapp

CMD ["myapp"]
