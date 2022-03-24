package main

import (
	"fmt"
	"github.com/BGrewell/go-iptables"
)

func main() {
	// Test to make sure that the format that wanemd needs is fully supported
	// c.IpTablesFmtString = "/sbin/iptables -A rule-%d -m physdev --physdev-out %s -o %s %s -j MARK --set-mark %d" // [rule.Id, device, bridge, filter, handle]
	mo := iptables.NewMatchGeneric("physdev", "physdev-out", "eth-up", false)

	r := &iptables.Rule{
		Id:           "rule-123",
		Name:         "serverXYZ",
		Table:        iptables.TableFilter,
		Chain:        iptables.ChainForward,
		IpVersion:    iptables.IPv4,
		TargetAction: iptables.ActionJump,
		Target: &iptables.TargetMark{
			Value: 0x123,
		},
	}
	r.AddMatch(mo)
	r.SetApp("wanemd")
	r.Debug = true

	err := r.Append()
	if err != nil {
		fmt.Printf("err: %s\n", err)
	} else {
		fmt.Println("Done!")
	}
}
