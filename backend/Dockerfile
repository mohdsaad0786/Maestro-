FROM golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /maestro ./cmd/maestro

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /maestro /maestro
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/maestro"]
