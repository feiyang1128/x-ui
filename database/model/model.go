package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"x-ui/core"
	"x-ui/util/json_util"
	"x-ui/xray"
)

type Protocol string

const (
	VMess       Protocol = "vmess"
	VLESS       Protocol = "vless"
	Hysteria2   Protocol = "hysteria2"
	Dokodemo    Protocol = "Dokodemo-door"
	Http        Protocol = "http"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
)

type User struct {
	Id       int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Inbound struct {
	Id         int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	UserId     int    `json:"-"`
	Up         int64  `json:"up" form:"up"`
	Down       int64  `json:"down" form:"down"`
	Total      int64  `json:"total" form:"total"`
	Remark     string `json:"remark" form:"remark"`
	Enable     bool   `json:"enable" form:"enable"`
	ExpiryTime int64  `json:"expiryTime" form:"expiryTime"`

	// config part
	Listen         string   `json:"listen" form:"listen"`
	Port           int      `json:"port" form:"port" gorm:"unique"`
	CoreType       string   `json:"coreType" form:"coreType"`
	Protocol       Protocol `json:"protocol" form:"protocol"`
	Settings       string   `json:"settings" form:"settings"`
	StreamSettings string   `json:"streamSettings" form:"streamSettings"`
	Tag            string   `json:"tag" form:"tag" gorm:"unique"`
	Sniffing       string   `json:"sniffing" form:"sniffing"`
}

func (i *Inbound) GetCoreType() core.Type {
	switch i.CoreType {
	case "", string(core.Xray):
		return core.Xray
	case string(core.SingBox):
		return core.SingBox
	default:
		return core.Xray
	}
}

func (i *Inbound) GenXrayInboundConfig() *xray.InboundConfig {
	listen := i.Listen
	if listen != "" {
		listen = fmt.Sprintf("\"%v\"", listen)
	}
	protocol := string(i.Protocol)
	if i.Protocol == Hysteria2 {
		protocol = "hysteria"
	}
	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(listen),
		Port:           i.Port,
		Protocol:       protocol,
		Settings:       json_util.RawMessage(i.Settings),
		StreamSettings: json_util.RawMessage(i.StreamSettings),
		Tag:            i.Tag,
		Sniffing:       json_util.RawMessage(i.Sniffing),
	}
}

func (i *Inbound) GenSingboxInboundConfig() (map[string]interface{}, error) {
	settings := map[string]interface{}{}
	if strings.TrimSpace(i.Settings) != "" {
		if err := json.Unmarshal([]byte(i.Settings), &settings); err != nil {
			return nil, err
		}
	}

	stream := map[string]interface{}{}
	if strings.TrimSpace(i.StreamSettings) != "" {
		if err := json.Unmarshal([]byte(i.StreamSettings), &stream); err != nil {
			return nil, err
		}
	}

	sniffing := map[string]interface{}{}
	if strings.TrimSpace(i.Sniffing) != "" {
		if err := json.Unmarshal([]byte(i.Sniffing), &sniffing); err != nil {
			return nil, err
		}
	}

	inbound := map[string]interface{}{
		"tag":         i.Tag,
		"listen_port": i.Port,
	}
	if i.Listen != "" {
		inbound["listen"] = i.Listen
	}

	if enabled, ok := sniffing["enabled"].(bool); ok {
		inbound["sniff"] = enabled
		if enabled {
			inbound["sniff_override_destination"] = true
		}
	}

	switch i.Protocol {
	case VMess:
		inbound["type"] = "vmess"
		inbound["users"] = buildSingboxUsers(settings, "clients", map[string]string{
			"id":      "uuid",
			"alterId": "alter_id",
		})
	case VLESS:
		inbound["type"] = "vless"
		inbound["users"] = buildSingboxUsers(settings, "clients", map[string]string{
			"id":   "uuid",
			"flow": "flow",
		})
	case Trojan:
		inbound["type"] = "trojan"
		inbound["users"] = buildSingboxUsers(settings, "clients", map[string]string{
			"password": "password",
			"flow":     "flow",
		})
	case Shadowsocks:
		inbound["type"] = "shadowsocks"
		copyOptionalValue(inbound, settings, "method", "method")
		copyOptionalValue(inbound, settings, "password", "password")
		copyOptionalValue(inbound, settings, "network", "network")
	case Http:
		inbound["type"] = "http"
		inbound["users"] = buildSingboxUsers(settings, "accounts", map[string]string{
			"user": "username",
			"pass": "password",
		})
	case Hysteria2:
		inbound["type"] = "hysteria2"
		auth := firstString(settings, "auth")
		if auth == "" {
			auth = firstClientString(settings, "clients", "auth")
		}
		if auth != "" {
			inbound["users"] = []map[string]interface{}{{"password": auth}}
		}
	default:
		return nil, errors.New("current inbound protocol is not supported by sing-box converter")
	}

	if err := applySingboxTransport(inbound, stream); err != nil {
		return nil, err
	}

	return inbound, nil
}

func buildSingboxUsers(settings map[string]interface{}, key string, fields map[string]string) []map[string]interface{} {
	rawUsers, ok := settings[key].([]interface{})
	if !ok {
		return nil
	}
	users := make([]map[string]interface{}, 0, len(rawUsers))
	for _, rawUser := range rawUsers {
		userMap, ok := rawUser.(map[string]interface{})
		if !ok {
			continue
		}
		user := map[string]interface{}{}
		for sourceKey, targetKey := range fields {
			copyOptionalValue(user, userMap, targetKey, sourceKey)
		}
		if len(user) > 0 {
			users = append(users, user)
		}
	}
	return users
}

func applySingboxTransport(inbound map[string]interface{}, stream map[string]interface{}) error {
	security, _ := stream["security"].(string)
	if security == "tls" || security == "xtls" {
		tlsSettings, _ := stream["tlsSettings"].(map[string]interface{})
		if security == "xtls" {
			tlsSettings, _ = stream["xtlsSettings"].(map[string]interface{})
		}
		tlsObj := map[string]interface{}{"enabled": true}
		copyOptionalValue(tlsObj, tlsSettings, "server_name", "serverName")
		copyOptionalValue(tlsObj, tlsSettings, "alpn", "alpn")
		if certificates, ok := tlsSettings["certificates"].([]interface{}); ok && len(certificates) > 0 {
			if cert, ok := certificates[0].(map[string]interface{}); ok {
				copyOptionalValue(tlsObj, cert, "certificate_path", "certificateFile")
				copyOptionalValue(tlsObj, cert, "key_path", "keyFile")
				copyOptionalValue(tlsObj, cert, "certificate", "certificate")
				copyOptionalValue(tlsObj, cert, "key", "key")
			}
		}
		inbound["tls"] = tlsObj
	}

	network, _ := stream["network"].(string)
	switch network {
	case "", "tcp":
		tcpSettings, _ := stream["tcpSettings"].(map[string]interface{})
		if tcpSettings != nil {
			header, _ := tcpSettings["header"].(map[string]interface{})
			if headerType, _ := header["type"].(string); headerType == "http" {
				return errors.New("sing-box does not support xray tcp http header transport conversion")
			}
		}
		return nil
	case "ws":
		wsSettings, _ := stream["wsSettings"].(map[string]interface{})
		transport := map[string]interface{}{"type": "ws"}
		copyOptionalValue(transport, wsSettings, "path", "path")
		copyOptionalValue(transport, wsSettings, "headers", "headers")
		inbound["transport"] = transport
		return nil
	case "http":
		httpSettings, _ := stream["httpSettings"].(map[string]interface{})
		transport := map[string]interface{}{"type": "http"}
		copyOptionalValue(transport, httpSettings, "path", "path")
		copyOptionalValue(transport, httpSettings, "host", "host")
		inbound["transport"] = transport
		return nil
	case "grpc":
		grpcSettings, _ := stream["grpcSettings"].(map[string]interface{})
		transport := map[string]interface{}{"type": "grpc"}
		copyOptionalValue(transport, grpcSettings, "service_name", "serviceName")
		inbound["transport"] = transport
		return nil
	case "hysteria":
		hysteriaSettings, _ := stream["hysteriaSettings"].(map[string]interface{})
		copyOptionalValue(inbound, hysteriaSettings, "up_mbps", "up_mbps")
		copyOptionalValue(inbound, hysteriaSettings, "down_mbps", "down_mbps")
		copyOptionalValue(inbound, hysteriaSettings, "ignore_client_bandwidth", "ignoreClientBandwidth")
		return nil
	default:
		return fmt.Errorf("stream network %q is not supported by sing-box converter", network)
	}
}

func copyOptionalValue(dest map[string]interface{}, src map[string]interface{}, destKey string, srcKey string) {
	if src == nil {
		return
	}
	value, ok := src[srcKey]
	if !ok {
		return
	}
	switch v := value.(type) {
	case string:
		if v == "" {
			return
		}
	case []interface{}:
		if len(v) == 0 {
			return
		}
	}
	dest[destKey] = value
}

func firstString(values map[string]interface{}, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return value
}

func firstClientString(values map[string]interface{}, key string, field string) string {
	clients, ok := values[key].([]interface{})
	if !ok || len(clients) == 0 {
		return ""
	}
	client, ok := clients[0].(map[string]interface{})
	if !ok {
		return ""
	}
	value, _ := client[field].(string)
	return value
}

type Setting struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Key   string `json:"key" form:"key"`
	Value string `json:"value" form:"value"`
}
