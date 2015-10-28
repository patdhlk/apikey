package apikey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/patdhlk/uuid"
)

var (
	ErrInvalidApiKey  = errors.New("Invalid Api Key")
	ErrEncodingFailed = errors.New("Api Key Encoding failed")
)

type KeyGen struct {
	HashedKey    string
	ClientSecret string
}

type ApiKey struct {
	Key   string `json:"k"`
	Name  string `json:"n"`
	OrgId int64  `json:"id"`
}

type ApiKeyDevice struct {
	Key   string `json:"k"`
	Name  string `json:"n"`
	DevId int64  `json:"id"`
}

func New(orgId int64, name string) KeyGen {
	apiKey := ApiKey{}
	apiKey.OrgId = orgId
	apiKey.Name = name
	apiKey.Key, _ = uuid.UUID()
	result := KeyGen{}
	result.HashedKey, _ = EncodePassword(apiKey.Key, name)

	jsonString, _ := json.Marshal(apiKey)

	result.ClientSecret = base64.StdEncoding.EncodeToString([]byte(jsonString))
	return result
}

func NewDeviceKeyGen(deviceId int64, name string) KeyGen {
	return New(deviceId, name)
}

//decodes the given key
func Decode(keyString string) (*ApiKey, error) {
	jsonString, err := base64.StdEncoding.DecodeString(keyString)
	if err != nil {
		return nil, ErrInvalidApiKey
	}

	var keyObj ApiKey
	err = json.Unmarshal([]byte(jsonString), &keyObj)
	if err != nil {
		return nil, ErrInvalidApiKey
	}

	return &keyObj, nil
}

//checks if a api key is valid
func IsValid(key *ApiKey, hashedKey string) bool {
	check, _ := EncodePassword(key.Key, key.Name)
	return check == hashedKey
}

// encodes the passwort with the given salt
func EncodePassword(password string, salt string) (string, error) {
	newPasswd, err := Key([]byte(password), []byte(salt), 16384, 8, 1, 32)
	if err != nil {
		return fmt.Sprintf("%x", newPasswd), ErrEncodingFailed
	}

	return fmt.Sprintf("%x", newPasswd), nil
}

func GetBasicAuthHeader(user string, password string) string {
	var userAndPass = user + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userAndPass))
}

func DecodeBasicAuthHeader(header string) (string, string, error) {
	var code string
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 && parts[0] == "Basic" {
		code = parts[1]
	}

	decoded, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		return "", "", err
	}

	userAndPass := strings.SplitN(string(decoded), ":", 2)
	if len(userAndPass) != 2 {
		return "", "", errors.New("Invalid basic auth header")
	}

	return userAndPass[0], userAndPass[1], nil
}
