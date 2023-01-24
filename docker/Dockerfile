FROM golang:alpine AS builder

WORKDIR /src
COPY . .

RUN apk add --no-cache git make
RUN apk add --no-cache gcc musl-dev pkgconf pcsc-lite-dev
RUN make V=1 build

FROM smallstep/step-cli:latest

COPY --from=builder /src/bin/step-kms-plugin /usr/local/bin/step-kms-plugin

USER root
RUN apk add --no-cache pcsc-lite pcsc-lite-libs
USER step

CMD ["/bin/bash"]