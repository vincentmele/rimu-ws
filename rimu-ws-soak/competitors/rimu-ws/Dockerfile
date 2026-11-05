# Built with the rimu-ws repository root as context (competitor.sh sends wtx, wtx-macros and this
# directory).
FROM rust:1.95-bookworm AS build
RUN rustup default nightly-2026-10-12
WORKDIR /src
COPY wtx ./wtx
COPY wtx-macros ./wtx-macros
COPY rimu-ws-soak/competitors/rimu-ws ./rimu-ws-soak/competitors/rimu-ws
WORKDIR /src/rimu-ws-soak/competitors/rimu-ws
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=build /src/rimu-ws-soak/competitors/rimu-ws/target/release/soak-competitor-rimu-ws /server
EXPOSE 8080
CMD ["/server"]
