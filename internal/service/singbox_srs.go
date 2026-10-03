package service

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/sagernet/sing/common/domain"
	"go4.org/netipx"
)

// compactSingBoxRules merges only identical condition sets. Mixing domain/IP/port
// conditions would change OR alternatives into AND conditions, so those stay separate.
func compactSingBoxRules(rules []sbObject) []sbObject {
	result := []sbObject{}
	groups := map[string]int{}
	for _, rule := range rules {
		keys := []string{}
		for key := range rule {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		encoded, _ := json.Marshal(keys)
		signature := string(encoded)
		index, exists := groups[signature]
		if !exists {
			index = len(result)
			groups[signature] = index
			result = append(result, sbObject{})
		}
		for _, key := range keys {
			switch values := rule[key].(type) {
			case []string:
				old, _ := result[index][key].([]string)
				result[index][key] = append(old, values...)
			case []int:
				old, _ := result[index][key].([]int)
				result[index][key] = append(old, values...)
			}
		}
	}
	return result
}

// compileSingBoxSRS implements the stable SRS v1 envelope and supported headless
// fields. Domain trie encoding is supplied by SagerNet's own matcher library.
// Format: SRS + version byte, zlib payload, uvarint rule count, default rules,
// typed items, 0xff terminator and false invert. See SagerNet/sing-box/common/srs.
func compileSingBoxSRS(source []byte) ([]byte, error) {
	var doc struct {
		Version int `json:"version"`
		Rules   []struct {
			Network         []string `json:"network"`
			Domain          []string `json:"domain"`
			Suffix          []string `json:"domain_suffix"`
			Keyword         []string `json:"domain_keyword"`
			Regex           []string `json:"domain_regex"`
			SourceIP        []string `json:"source_ip_cidr"`
			IP              []string `json:"ip_cidr"`
			SourcePort      []uint16 `json:"source_port"`
			SourcePortRange []string `json:"source_port_range"`
			Port            []uint16 `json:"port"`
			PortRange       []string `json:"port_range"`
			ProcessName     []string `json:"process_name"`
			ProcessPath     []string `json:"process_path"`
		} `json:"rules"`
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("SRS 编译仅支持 source-v1")
	}
	var output bytes.Buffer
	output.Write([]byte{'S', 'R', 'S', 1})
	compressor, err := zlib.NewWriterLevel(&output, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	writer := bufio.NewWriter(compressor)
	uvarint := func(v uint64) error {
		var b [10]byte
		n := binary.PutUvarint(b[:], v)
		_, e := writer.Write(b[:n])
		return e
	}
	stringsItem := func(kind byte, values []string) error {
		if len(values) == 0 {
			return nil
		}
		if e := writer.WriteByte(kind); e != nil {
			return e
		}
		if e := uvarint(uint64(len(values))); e != nil {
			return e
		}
		for _, v := range values {
			if e := uvarint(uint64(len(v))); e != nil {
				return e
			}
			if _, e := writer.WriteString(v); e != nil {
				return e
			}
		}
		return nil
	}
	portsItem := func(kind byte, values []uint16) error {
		if len(values) == 0 {
			return nil
		}
		if e := writer.WriteByte(kind); e != nil {
			return e
		}
		if e := uvarint(uint64(len(values))); e != nil {
			return e
		}
		return binary.Write(writer, binary.BigEndian, values)
	}
	cidrItem := func(kind byte, values []string) error {
		if len(values) == 0 {
			return nil
		}
		var builder netipx.IPSetBuilder
		for _, v := range values {
			prefix, e := netip.ParsePrefix(v)
			if e != nil {
				return e
			}
			builder.AddPrefix(prefix)
		}
		set, e := builder.IPSet()
		if e != nil {
			return e
		}
		ranges := set.Ranges()
		if e = writer.WriteByte(kind); e != nil {
			return e
		}
		if e = writer.WriteByte(1); e != nil {
			return e
		}
		if e = binary.Write(writer, binary.BigEndian, uint64(len(ranges))); e != nil {
			return e
		}
		for _, r := range ranges {
			for _, addr := range []netip.Addr{r.From(), r.To()} {
				raw := addr.AsSlice()
				if e = uvarint(uint64(len(raw))); e != nil {
					return e
				}
				if _, e = writer.Write(raw); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if err = uvarint(uint64(len(doc.Rules))); err != nil {
		return nil, err
	}
	for _, r := range doc.Rules {
		if err = writer.WriteByte(0); err != nil {
			return nil, err
		}
		if err = stringsItem(1, r.Network); err != nil {
			return nil, err
		}
		if len(r.Domain) > 0 || len(r.Suffix) > 0 {
			if err = writer.WriteByte(2); err != nil {
				return nil, err
			}
			if err = domain.NewMatcher(r.Domain, r.Suffix, true).Write(writer); err != nil {
				return nil, err
			}
		}
		for _, item := range []struct {
			kind   byte
			values []string
		}{{3, r.Keyword}, {4, r.Regex}} {
			if err = stringsItem(item.kind, item.values); err != nil {
				return nil, err
			}
		}
		if err = cidrItem(5, r.SourceIP); err != nil {
			return nil, err
		}
		if err = cidrItem(6, r.IP); err != nil {
			return nil, err
		}
		if err = portsItem(7, r.SourcePort); err != nil {
			return nil, err
		}
		if err = stringsItem(8, r.SourcePortRange); err != nil {
			return nil, err
		}
		if err = portsItem(9, r.Port); err != nil {
			return nil, err
		}
		for _, item := range []struct {
			kind   byte
			values []string
		}{{10, r.PortRange}, {11, r.ProcessName}, {12, r.ProcessPath}} {
			if err = stringsItem(item.kind, item.values); err != nil {
				return nil, err
			}
		}
		if err = writer.WriteByte(0xff); err != nil {
			return nil, err
		}
		if err = writer.WriteByte(0); err != nil {
			return nil, err
		}
	}
	if err = writer.Flush(); err != nil {
		return nil, err
	}
	if err = compressor.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func cachedSingBoxSRS(source []byte) ([]byte, error) {
	key := fmt.Sprintf("srs-v1:%x", sha256.Sum256(source))
	singBoxRuleCache.Lock()
	entry, exists := singBoxRuleCache.entries[key]
	singBoxRuleCache.Unlock()
	if exists && time.Now().Before(entry.expires) {
		return entry.data, nil
	}
	data, err := compileSingBoxSRS(source)
	if err != nil {
		return nil, err
	}
	singBoxRuleCache.Lock()
	if len(singBoxRuleCache.entries) >= 16 {
		clear(singBoxRuleCache.entries)
	}
	singBoxRuleCache.entries[key] = struct {
		data    []byte
		expires time.Time
	}{data, time.Now().Add(5 * time.Minute)}
	singBoxRuleCache.Unlock()
	return data, nil
}

// CompileSingBoxRuleSet returns a cached SRS v1 representation of native source rules.
func CompileSingBoxRuleSet(source []byte) ([]byte, error) { return cachedSingBoxSRS(source) }
