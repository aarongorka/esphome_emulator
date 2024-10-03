.ONESHELL:
.SHELLFLAGS += -euo pipefail

.PHONY: proto
proto:
	pushd ./esphome_emulator/
	curl -LsO https://github.com/esphome/esphome/raw/refs/heads/dev/esphome/components/api/api.proto
	curl -LsO https://github.com/esphome/esphome/raw/refs/heads/dev/esphome/components/api/api_options.proto
	protoc -I . --python_out=. api_options.proto api.proto --mypy_out=.
	sed -i 's/import api_options_pb2 as api__options__pb2/from . import api_options_pb2 as api__options__pb2/g' api_pb2.py
