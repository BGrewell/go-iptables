package iptables

import (
	"fmt"
	"github.com/BGrewell/go-execute"
	"github.com/BGrewell/go-iptables/internal"
	"github.com/google/uuid"
	"log"
	"strings"
)

func Sync() (rules []*Rule, err error) {

	if !internal.RunningAsRoot() {
		return nil, fmt.Errorf("error you must run this program as root")
	}

	ipvers := []string{"ipv4", "ipv6"}
	rules = make([]*Rule, 0)

	for _, ipver := range ipvers {

		var ipt string
		ipt, err = internal.GetIptablesBinaryPath(ipver)
		if err != nil {
			return nil, err
		}

		for _, table := range tables {

			var tableRules string
			cmd := fmt.Sprintf("%s -t %s -S", ipt, table)
			tableRules, err = execute.ExecuteCmd(cmd)
			if err != nil {
				return nil, err
			}

			tableLines := strings.Split(tableRules, "\n")
			ruleNumbers := make(map[string]int)
			for _, line := range tableLines {
				if strings.HasPrefix(line, "-A") || strings.HasPrefix(line, "-I") {
					r := Rule{}
					r.IpVersion = IPVer(ipver)
					err = r.Parse(table, line)
					if err != nil {
						return nil, err
					}
					if _, ok := ruleNumbers[string(r.Chain)]; !ok {
						ruleNumbers[string(r.Chain)] = 0
					}
					ruleNumbers[string(r.Chain)] += 1
					r.Number = ruleNumbers[string(r.Chain)]
					rules = append(rules, &r)
				}
			}
		}

	}

	return rules, nil
}

func LabelRules() (err error) {
	rules, err := Sync()
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if rule.Id == "" {
			id := uuid.New().String()
			rule.Id = id
			fmt.Println(rule)
			err := rule.Replace()
			if err != nil {
				log.Printf("failed to set id: %v\n", err)
			}
		}
	}
	return nil
}

func CurrentRules() (rules []*Rule, err error) {
	return Sync()
}