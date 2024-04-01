FROM golang:alpine AS builder

WORKDIR /build/

COPY . .

RUN go build

FROM scratch

COPY --from=builder /build/kube-image-update /usr/bin/kube-image-update

ENTRYPOINT ["/usr/bin/kube-image-update"]