FROM golang:alpine AS builder

WORKDIR /build/

COPY . .

RUN go build

FROM alpine

COPY --from=builder /build/kube-image-update /usr/bin/kube-image-update

ENTRYPOINT ["kube-image-update"]