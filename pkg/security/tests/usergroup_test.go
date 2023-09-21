// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build functionaltests

// Package tests holds tests related files
package tests

import (
	"os/exec"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

func TestUserGroup(t *testing.T) {
	ruleDefs := []*rules.RuleDefinition{
		&rules.RuleDefinition{
			ID:         "test_rule_user",
			Expression: `open.file.path == "/tmp/test" && open.flags & O_CREAT != 0 && open.file.uid == 999 && open.file.user == "testuser"`,
		},
		&rules.RuleDefinition{
			ID:         "test_rule_group",
			Expression: `open.file.path == "/tmp/test2" && open.flags & O_CREAT != 0 && open.file.gid == 999 && open.file.group == "testgroup"`,
		},
	}

	test, err := newTestModule(t, nil, ruleDefs, testOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	dockerWrapper, err := newDockerCmdWrapper(test.Root(), test.Root(), "ubuntu")
	if err != nil {
		t.Skipf("Skipping sbom tests: Docker not available: %s", err)
		return
	}
	defer dockerWrapper.stop()

	if _, err := dockerWrapper.start(); err != nil {
		t.Fatal(err)
	}

	dockerWrapper.RunTest(t, "groupadd", func(t *testing.T, kind wrapperType, cmdFunc func(bin string, args, env []string) *exec.Cmd) {
		test.WaitSignal(t, func() error {
			return cmdFunc("/sbin/groupadd", []string{"--gid", "999", "testgroup"}, nil).Run()
		}, func(event *model.Event, rule *rules.Rule) {
			assertTriggeredRule(t, rule, "refresh_group_cache")
		})
	})

	dockerWrapper.RunTest(t, "useradd", func(t *testing.T, kind wrapperType, cmdFunc func(bin string, args, env []string) *exec.Cmd) {
		test.WaitSignal(t, func() error {
			return cmdFunc("/sbin/useradd", []string{"--gid", "999", "--uid", "999", "testuser"}, nil).Run()
		}, func(event *model.Event, rule *rules.Rule) {
			assertTriggeredRule(t, rule, "refresh_user_cache")
		})
	})

	dockerWrapper.RunTest(t, "user", func(t *testing.T, kind wrapperType, cmdFunc func(bin string, args, env []string) *exec.Cmd) {
		test.WaitSignal(t, func() error {
			return cmdFunc("/usr/bin/su", []string{"--command", "/usr/bin/touch /tmp/test", "testuser"}, nil).Run()
		}, func(event *model.Event, rule *rules.Rule) {
			assertTriggeredRule(t, rule, "test_rule_user")

			test.validateOpenSchema(t, event)
		})
	})

	dockerWrapper.RunTest(t, "group", func(t *testing.T, kind wrapperType, cmdFunc func(bin string, args, env []string) *exec.Cmd) {
		test.WaitSignal(t, func() error {
			return cmdFunc("/usr/bin/su", []string{"-g", "testgroup", "--command", "/usr/bin/touch /tmp/test2"}, nil).Run()
		}, func(event *model.Event, rule *rules.Rule) {
			assertTriggeredRule(t, rule, "test_rule_group")

			test.validateOpenSchema(t, event)
		})
	})
}
