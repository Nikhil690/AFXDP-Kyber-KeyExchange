package xdp

import (
	"github.com/cilium/ebpf"
	"github.com/slavc/xdp"
)

func NewIPProtoProgram(protocol uint32, options *ebpf.CollectionOptions) (*xdp.Program, error) {
	spec, err := loadXdp()
	if err != nil {
		return nil, err
	}

	// if protocol >= 0 && protocol <= 255 {
	// 	if err := spec.RewriteConstants(map[string]any{"PROTO": uint8(protocol)}); err != nil {
	// 		return nil, err
	// 	}
	// } else {
	// 	return nil, fmt.Errorf("protocol must be between 0 and 255")
	// }
	var program xdpObjects
	if err := spec.LoadAndAssign(&program, options); err != nil {
		return nil, err
	}

	p := &xdp.Program{Program: program.XdpSockProg, Queues: program.QidconfMap, Sockets: program.XsksMap}
	return p, nil
}
