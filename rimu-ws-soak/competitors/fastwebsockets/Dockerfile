FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=build /src/target/release/soak-competitor-fastwebsockets /server
EXPOSE 8080
CMD ["/server"]
