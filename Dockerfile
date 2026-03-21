FROM rust:1.94-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --bin fort --bin fortd --bin fort-agent

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/fort
COPY --from=build /src/target/release/fortd /usr/local/bin/fortd
COPY --from=build /src/target/release/fort /usr/local/bin/fort
COPY --from=build /src/target/release/fort-agent /usr/local/bin/fort-agent
COPY config/fortd.container.toml /etc/fort/fortd.toml

VOLUME ["/var/lib/fort"]
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/usr/local/bin/fort", "--host", "http://127.0.0.1:8088", "doctor"]
ENTRYPOINT ["/usr/local/bin/fortd", "--config-file", "/etc/fort/fortd.toml"]
