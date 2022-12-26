// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apiutil

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/fatih/color"
	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

// workaround. This for the json format compatibility. Once we update senario tests, we can remove this.
type Path struct {
	Nlri       bgp.AddrPrefixInterface      `json:"nlri"`
	Age        int64                        `json:"age"`
	Best       bool                         `json:"best"`
	Attrs      []bgp.PathAttributeInterface `json:"attrs"`
	Stale      bool                         `json:"stale"`
	Withdrawal bool                         `json:"withdrawal,omitempty"`
	SourceID   net.IP                       `json:"source-id,omitempty"`
	NeighborIP net.IP                       `json:"neighbor-ip,omitempty"`
}

type Destination struct {
	Paths []*Path
}

func (d *Destination) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Paths)
}

func NewDestination(dst *api.Destination) *Destination {
	l := make([]*Path, 0, len(dst.Paths))
	for _, p := range dst.Paths {
		nlri, _ := GetNativeNlri(p)
		attrs, _ := GetNativePathAttributes(p)
		l = append(l, &Path{
			Nlri:       nlri,
			Age:        p.Age.AsTime().Unix(),
			Best:       p.Best,
			Attrs:      attrs,
			Stale:      p.Stale,
			Withdrawal: p.IsWithdraw,
			SourceID:   net.ParseIP(p.SourceId),
			NeighborIP: net.ParseIP(p.NeighborIp),
		})
	}
	return &Destination{Paths: l}
}

func NewPath(nlri bgp.AddrPrefixInterface, isWithdraw bool, attrs []bgp.PathAttributeInterface, age time.Time) (*api.Path, error) {
	n, err := MarshalNLRI(nlri)
	if err != nil {
		return nil, err
	}
	a, err := MarshalPathAttributes(attrs)
	if err != nil {
		return nil, err
	}
	return &api.Path{
		Nlri:       n,
		Pattrs:     a,
		Age:        tspb.New(age),
		IsWithdraw: isWithdraw,
		Family:     ToApiFamily(nlri.AFI(), nlri.SAFI()),
		Identifier: nlri.PathIdentifier(),
	}, nil
}

func getNLRI(family bgp.RouteFamily, buf []byte) (bgp.AddrPrefixInterface, error) {
	afi, safi := bgp.RouteFamilyToAfiSafi(family)
	nlri, err := bgp.NewPrefixFromRouteFamily(afi, safi)
	if err != nil {
		return nil, err
	}
	if err := nlri.DecodeFromBytes(buf); err != nil {
		return nil, err
	}
	return nlri, nil
}

func GetNativeNlri(p *api.Path) (bgp.AddrPrefixInterface, error) {
	if p.Family == nil {
		return nil, fmt.Errorf("family cannot be nil")
	}
	if len(p.NlriBinary) > 0 {
		return getNLRI(ToRouteFamily(p.Family), p.NlriBinary)
	}
	return UnmarshalNLRI(ToRouteFamily(p.Family), p.Nlri)
}

func GetNativePathAttributes(p *api.Path) ([]bgp.PathAttributeInterface, error) {
	pattrsLen := len(p.PattrsBinary)
	if pattrsLen > 0 {
		pattrs := make([]bgp.PathAttributeInterface, 0, pattrsLen)
		for _, attr := range p.PattrsBinary {
			a, err := bgp.GetPathAttribute(attr)
			if err != nil {
				return nil, err
			}
			err = a.DecodeFromBytes(attr)
			if err != nil {
				return nil, err
			}
			pattrs = append(pattrs, a)
		}
		return pattrs, nil
	}
	return UnmarshalPathAttributes(p.Pattrs)
}

func ToRouteFamily(f *api.Family) bgp.RouteFamily {
	return bgp.AfiSafiToRouteFamily(uint16(f.Afi), uint8(f.Safi))
}

func ToApiFamily(afi uint16, safi uint8) *api.Family {
	return &api.Family{
		Afi:  api.Family_Afi(afi),
		Safi: api.Family_Safi(safi),
	}
}

type OpaqueSignaling struct {
	Key []Opaque `json:"srv6-epe-sid"`
}

type Opaque struct {
	Nlri KeyValue `json:"nlri"`
}

type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func GetSrv6EpeSid() (string, string, error) {
	var out string
	var sid string
	var nh6 string
	out, _ = LocalExecutef("ip -6 route | grep End.DX6")
	epeRoute := strings.Split(out, " ")
	if len(epeRoute) < 1 {
		out, err := LocalExecutef("/gobgp global rib -a opaque -j")
		if err != nil {
			return "", "", err
		}

		var opasig OpaqueSignaling
		json.Unmarshal([]byte(out), &opasig)
		sid = opasig.Key[0].Nlri.Value
		return sid, "", err
	}
	sid = epeRoute[0]
	for i, r := range epeRoute {
		if r == "nh6" {
			nh6 = epeRoute[i+1]
		}
	}
	if nh6 == "" {
		return "", "", nil
	}
	return sid, nh6, nil
}

func LocalExecute(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		str := fmt.Sprintf("CommandExecute [%s] ", cmd)
		str += fmt.Sprintf(color.RedString("Failed"))
		str += fmt.Sprintf(color.RedString("%s", err.Error()))
		fmt.Printf("%s\n", str)
		return "", err
	}

	str := fmt.Sprintf("CommandExecute [%s] ", cmd)
	str += fmt.Sprintf(color.GreenString("Success"))
	fmt.Printf("%s\n", str)
	return string(out), nil
}

func LocalExecutef(fs string, a ...interface{}) (string, error) {
	cmd := fmt.Sprintf(fs, a...)
	return LocalExecute(cmd)
}

// func AdvertiseSrv6EpeSid() {
// 	sid, nh6, err := GetSrv6EpeSid()
// 	if err != nil {
// 		return
// 	}
// 	attrs := make([]bgp.PathAttributeInterface, 0, 1)
// 	attrs = append(attrs, bgp.NewPathAttributeMpReachNLRI(nh6))
// 	bgp.NewBGPUpdateMessage(nil, attrs, nil)
// }
