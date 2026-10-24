# Railway builds this file. Build stage compiles the release binary; runtime is distroless (glibc, CA certs, nonroot).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations ./migrations
COPY templates ./templates
COPY src ./src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/vekrel-relay /usr/local/bin/vekrel-relay
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vekrel-relay"]
CMD ["serve"]
