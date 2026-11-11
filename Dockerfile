FROM docker.io/library/rust:1.96 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/opslab-gateway /opslab-gateway
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/opslab-gateway"]
