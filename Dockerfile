FROM alpine:latest

ADD k8s-log-aggregator /k8s-log-aggregator
ENTRYPOINT ["./k8s-log-aggregator"]