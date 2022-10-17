package encrypt

import (
	"encoding/base64"
	"fmt"
	"github.com/cihub/seelog"
)

//CreateSecData 加密数据
//首先对数据进行base64加密，然后进行aes加密，并将得到的结果做base64加密
//然后将密钥加到加密后的string的头部
//然后对得到的字符串做base64加密
//n为密钥长度,密钥长度不能低于16个byte
// data ->[base64]=str1 ->[aes](aeskey)=str2 -> [base64]=str3 ->aeskey+str3=str4 -> [base64]=result
func CreateSecData(data string, pwd string) (secdata string, ok bool) {

	data = base64.StdEncoding.EncodeToString([]byte(data))
	aesEnc := AesEncrypt{}
	aesEnc.PrivateCode = pwd
	arrEncrypt, err := aesEnc.Encrypt(data)
	if err != nil {
		fmt.Println("CreateSecData err:", err)
		return "", false
	}
	secdata =   base64.StdEncoding.EncodeToString(arrEncrypt)
	secdata = base64.StdEncoding.EncodeToString([]byte(secdata))
	return secdata, true
}

//ParseSecData 解密数据
//首先对数据进行base64反解，然后取出密钥，长度为n,在字符串的头部
//然后对密钥后边的字符串进行base64反解
//然后用密钥把得到的字符串aes解密
//解析出来的string，再做一次base64反解，即为数据
func ParseSecData(secdata string, pwd string) (data string, ok bool) {

	secdataB, err1 := base64.StdEncoding.DecodeString(secdata)
	if err1 != nil {
		seelog.Debug("ParseSecData base64.StdEncoding.DecodeString err1:", err1)
		return "", false
	}
	secdata = string(secdataB)

	//lenth := len(secdata)
	aesEnc := AesEncrypt{}

	aesEnc.PrivateCode = pwd

	message, err2 := base64.StdEncoding.DecodeString(secdata)
	if err2 != nil {
		seelog.Debug("ParseSecData base64.StdEncoding.DecodeString err2:", err2)
		return "", false
	}

	var err error
	data, err = aesEnc.Decrypt(message)
	if err != nil {
		seelog.Debug("ParseSecData aesEnc.Decrypt err:", err)
		return "", false
	}

	//seelog.Debug("aesDec data : ", data)

	if dataB, err := base64.StdEncoding.DecodeString(data); err != nil {
		seelog.Debug("ParseSecData base64.StdEncoding.DecodeString err:", err)
		return "", false
	} else {
		data = string(dataB)
	}
	return data, true
}
