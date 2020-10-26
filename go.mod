module github.com/projectrekor/rekor-cli

go 1.14

require (
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/etcd v3.3.18+incompatible // indirect
	github.com/google/certificate-transparency-go v1.1.0 // indirect
	github.com/google/trillian v1.3.10
	github.com/mitchellh/go-homedir v1.1.0
	github.com/projectrekor/rekor-server v0.0.0-20201020185212-eabecb525492
	github.com/prometheus/common v0.10.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.1
	go.etcd.io/etcd v3.3.25+incompatible // indirect
	go.uber.org/zap v1.16.0
)

replace google.golang.org/grpc => google.golang.org/grpc v1.29.1
