package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp ../ebpf/xdp_program.c
