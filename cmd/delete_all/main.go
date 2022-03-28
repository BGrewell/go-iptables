package main

import (
	"bufio"
	"fmt"
	"github.com/BGrewell/go-iptables"
	"os"
)

func main() {

	mo := iptables.NewMatchGeneric("physdev", "physdev-out", "eth-up", false)
	mi := iptables.NewMatchGeneric("physdev", "physdev-in", "eth-dn", false)
	r := &iptables.Rule{
		Id:           "rule-2-ul-0",
		Name:         "super-test-ul-0",
		Table:        iptables.TableFilter,
		Chain:        iptables.ChainForward,
		IpVersion:    iptables.IPv4,
		TargetAction: iptables.ActionJump,
		Target: &iptables.TargetMark{
			Value: 0x123,
		},
	}
	r.AddMatch(mo)
	r.SetApp("wanemd-super-test")
	r.Debug = true

	err := r.Append()
	if err != nil {
		fmt.Printf("err: %s\n", err)
	} else {
		fmt.Println("added ul-rule")
	}

	r = &iptables.Rule{
		Id:           "rule-2-dl-0",
		Name:         "super-test-dl-0",
		Table:        iptables.TableFilter,
		Chain:        iptables.ChainForward,
		IpVersion:    iptables.IPv4,
		TargetAction: iptables.ActionJump,
		Target: &iptables.TargetMark{
			Value: 0x123,
		},
	}
	r.AddMatch(mi)
	r.SetApp("wanemd-super-test")
	r.Debug = true

	err = r.Append()
	if err != nil {
		fmt.Printf("err: %s\n", err)
	} else {
		fmt.Println("added dl-rule")
	}

	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	fmt.Println("attempting to delete rules")

	err = iptables.DeleteAllMatchingApp("wanemd-super-test")
	if err != nil {
		fmt.Printf("err: %s\n", err)
	} else {
		fmt.Println("deleted rules")
	}

}
