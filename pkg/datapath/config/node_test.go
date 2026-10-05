// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// TestNodeConfigIPMasqAgentIPv4 verifies that the enable_ip_masq_agent_ipv4
// node config variable is only set when BPF masquerading, IPv4 masquerading
// and the ip-masq-agent are all enabled, matching the semantics of the
// previous ENABLE_IP_MASQ_AGENT_IPV4 compile-time define.
func TestNodeConfigIPMasqAgentIPv4(t *testing.T) {
	oldBPFMasq := option.Config.EnableBPFMasquerade
	oldIPv4Masq := option.Config.EnableIPv4Masquerade
	oldIPMasqAgent := option.Config.EnableIPMasqAgent
	t.Cleanup(func() {
		option.Config.EnableBPFMasquerade = oldBPFMasq
		option.Config.EnableIPv4Masquerade = oldIPv4Masq
		option.Config.EnableIPMasqAgent = oldIPMasqAgent
	})

	tests := []struct {
		name        string
		bpfMasq     bool
		ipv4Masq    bool
		ipMasqAgent bool
		expected    bool
	}{
		{"all enabled", true, true, true, true},
		{"BPF masquerade disabled", false, true, true, false},
		{"IPv4 masquerade disabled", true, false, true, false},
		{"ip-masq-agent disabled", true, true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.EnableBPFMasquerade = tt.bpfMasq
			option.Config.EnableIPv4Masquerade = tt.ipv4Masq
			option.Config.EnableIPMasqAgent = tt.ipMasqAgent

			node := NodeConfig(&Config{})
			assert.Equal(t, tt.expected, node.EnableIPMasqAgentIPv4)
		})
	}
}

// TestPolicyVerdictNotifyConfig verifies that the runtime
// enable_policy_verdict_notify setting uses the node value by default
// and can be enabled or disabled per endpoint.
func TestPolicyVerdictNotifyConfig(t *testing.T) {
	oldOpts := option.Config.Opts
	option.Config.Opts = option.NewIntOptions(&option.DaemonMutableOptionLibrary)
	t.Cleanup(func() { option.Config.Opts = oldOpts })

	ep := testutils.NewTestEndpoint(t)
	hostEP := testutils.NewTestHostEndpoint(t)
	lnc := &Config{}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Index:        1,
		HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
	}}

	for _, tt := range []struct {
		name            string
		nodeEnabled     bool
		endpointEnabled bool
	}{
		{name: "endpoint disables node default", nodeEnabled: true},
		{name: "endpoint enables node default", endpointEnabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.Opts.SetBool(option.PolicyVerdictNotify, tt.nodeEnabled)
			ep.Opts.SetBool(option.PolicyVerdictNotify, tt.endpointEnabled)
			hostEP.Opts.SetBool(option.PolicyVerdictNotify, tt.endpointEnabled)

			for _, attachment := range []struct {
				name string
				cfg  any
				want bool
			}{
				{"node", NodeConfig(lnc), tt.nodeEnabled},
				{"endpoint", Endpoint(&ep, lnc), tt.endpointEnabled},
				{"cilium_host", CiliumHost(&hostEP, lnc), tt.endpointEnabled},
				{"cilium_net", CiliumNet(&hostEP, lnc, link), tt.endpointEnabled},
				{"netdev", Netdev(&hostEP, lnc, link, netip.Addr{}, netip.Addr{}), tt.endpointEnabled},
			} {
				t.Run(attachment.name, func(t *testing.T) {
					constants, err := Map(attachment.cfg)
					require.NoError(t, err)
					assert.Equal(t, attachment.want, constants["enable_policy_verdict_notify"])
				})
			}
		})
	}
}
