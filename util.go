package wxpay

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"golang.org/x/crypto/pkcs12"
	"io"
	"log"
	"strconv"
	"strings"
	"time"
)

// ToJSON 转化成JSON字符
func (p Params) ToJSON() string {
	mjson, _ := json.Marshal(p)
	return string(mjson)
}

// Decode XML解码
func Decode(r io.Reader) Params {
	var (
		d      *xml.Decoder
		start  *xml.StartElement
		params Params
	)
	d = xml.NewDecoder(r)
	params = make(Params)
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			start = &t
		case xml.CharData:
			if t = bytes.TrimSpace(t); len(t) > 0 {
				params.SetString(start.Name.Local, string(t))
			}
		}
	}
	return params
}

//// Encode XML编码
//func Encode(params Params) io.Reader {
//	var buf bytes.Buffer
//	buf.WriteString(``)
//	for k, v := range params {
//		buf.WriteString(`<`)
//		buf.WriteString(k)
//		buf.WriteString(`>`)
//	}
//	buf.WriteString(``)
//	return &buf
//}

func XmlToMap(xmlStr string) Params {
	return Decode(strings.NewReader(xmlStr))
	//params := make(Params)
	//decoder := xml.NewDecoder(strings.NewReader(xmlStr))
	//
	//var (
	//	key   string
	//	value string
	//)
	//
	//for t, err := decoder.Token(); err == nil; t, err = decoder.Token() {
	//	switch token := t.(type) {
	//	case xml.StartElement: // 开始标签
	//		key = token.Name.Local
	//	case xml.CharData: // 标签内容
	//		content := string([]byte(token))
	//		value = content
	//	}
	//	if key != "xml" {
	//		if value != "\n" {
	//			params.SetString(key, value)
	//		}
	//	}
	//}
	//
	//return params
}

func MapToXml(params Params) string {
	var buf bytes.Buffer
	buf.WriteString(`<xml>`)
	for k, v := range params {
		buf.WriteString(`<`)
		buf.WriteString(k)
		buf.WriteString(`><![CDATA[`)
		buf.WriteString(v)
		buf.WriteString(`]]></`)
		buf.WriteString(k)
		buf.WriteString(`>`)
	}
	buf.WriteString(`</xml>`)

	return buf.String()
}

// 用时间戳生成随机字符串
func nonceStr() string {
	return strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
}

// 将Pkcs12转成Pem
func pkcs12ToPem(p12 []byte, password string) tls.Certificate {

	blocks, err := pkcs12.ToPEM(p12, password)

	// 从恐慌恢复
	defer func() {
		if x := recover(); x != nil {
			log.Print(x)
		}
	}()

	if err != nil {
		panic(err)
	}

	var pemData []byte
	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		panic(err)
	}
	return cert
}
