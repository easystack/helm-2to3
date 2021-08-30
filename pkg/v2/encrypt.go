/*
Copyright (c) 2017 Easystack, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v2

import (
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha256"
	"errors"
	"io/ioutil"

	"k8s.io/helm/pkg/proto/hapi/chart"
	"k8s.io/helm/pkg/proto/hapi/release"
)

var sum = sha256.Sum224([]byte("08ff80583883217bb07ed23728aa8511"))
var key = sum[:24]

var magicGzip = []byte{0x1f, 0x8b, 0x08}



// TripleDesDecrypt decrypted byte stream.
func TripleDesDecrypt(cryptedData []byte) (_ []byte, err error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	defer func() {
		if recover() != nil {
			err = errors.New("prohibit the installation of unauthorized software packages")
		}
	}()
	blockMode := cipher.NewCBCDecrypter(block, key[:8])
	origData := make([]byte, len(cryptedData))
	blockMode.CryptBlocks(origData, cryptedData)
	origData = PKCS5UnPadding(origData)

	origData, err = decodeRelease(origData)
	if err != nil {
		return nil, err
	}

	return origData, nil
}


// PKCS5UnPadding block unpadding.
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}



// ChartValuesDecrypt decrypt chart values.
func ChartValuesDecrypt(values string) (string, error) {
	valuesData := []byte(values)
	valuesData, err := TripleDesDecrypt(valuesData)
	if err != nil {
		return values, err
	}
	return string(valuesData), nil
}



// ChartTemplatesDecrypt decrypt chart templates.
func ChartTemplatesDecrypt(templates []*chart.Template) ([]*chart.Template, error) {
	for _, v := range templates {
		var err error
		v.Data, err = TripleDesDecrypt(v.GetData())
		if err != nil {
			return templates, err
		}
	}
	return templates, nil
}



// HooksDecrypt decrypt hooks.
func HooksDecrypt(hooks []*release.Hook) ([]*release.Hook, error) {
	for _, h := range hooks {
		valuesData := []byte(h.Manifest)
		valuesData, err := TripleDesDecrypt(valuesData)
		if err != nil {
			return hooks, err
		}
		h.Manifest = string(valuesData)
	}
	return hooks, nil
}

// ChartDecrypt decrypt chart.
func ChartDecrypt(chart *chart.Chart) (*chart.Chart, error) {
	var err error
	chart.Values.Raw, err = ChartValuesDecrypt(chart.Values.Raw)
	if err != nil {
		return nil, err
	}
	chart.Templates, err = ChartTemplatesDecrypt(chart.Templates)
	if err != nil {
		return nil, err
	}
	return chart, nil
}



// ReleaseDecrypt decrypt release.
func ReleaseDecrypt(release *release.Release) (*release.Release, error) {
	var err error
	release.Chart, err = ChartDecrypt(release.Chart)
	if err != nil {
		return nil, err
	}
	release.Manifest, err = ChartValuesDecrypt(release.Manifest)
	if err != nil {
		return nil, err
	}
	release.Config.Raw, err = ChartValuesDecrypt(release.Config.Raw)
	if err != nil {
		return nil, err
	}
	release.Hooks, err = HooksDecrypt(release.Hooks)
	if err != nil {
		return nil, err
	}
	return release, nil
}


// decodeRelease decodes the bytes in data.
func decodeRelease(data []byte) ([]byte, error) {
	// For backwards compatibility with releases that were stored before
	// compression was introduced we skip decompression if the
	// gzip magic header is not found
	if bytes.Equal(data[0:3], magicGzip) {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		b2, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
		data = b2
	}

	return data, nil
}
