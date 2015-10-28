package apikey

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestEncoding(t *testing.T) {

	Convey("When generating base64 header", t, func() {
		result := GetBasicAuthHeader("patdhlk", "0602")

		So(result, ShouldEqual, "Basic cGF0ZGhsazowNjAy")
	})

	Convey("When decoding basic auth header", t, func() {
		header := GetBasicAuthHeader("patdhlk", "0602")
		username, password, err := DecodeBasicAuthHeader(header)
		So(err, ShouldBeNil)

		So(username, ShouldEqual, "patdhlk")
		So(password, ShouldEqual, "0602")
	})

}

func TestApiKeyGeneration(t *testing.T) {

	Convey("When generating new api key", t, func() {
		result := New(69, "The most usable elitess water key")

		So(result.ClientSecret, ShouldNotBeEmpty)
		So(result.HashedKey, ShouldNotBeEmpty)

		Convey("can decode key", func() {
			keyInfo, err := Decode(result.ClientSecret)
			So(err, ShouldBeNil)

			keyHashed, err := EncodePassword(keyInfo.Key, keyInfo.Name)
			So(err, ShouldBeNil)
			So(keyHashed, ShouldEqual, result.HashedKey)
		})

		Convey("valid key", func() {
			keyInfo, err := Decode(result.ClientSecret)

			So(err, ShouldBeNil)
			b := IsValid(keyInfo, result.HashedKey)
			So(b, ShouldEqual, true)
		})
	})
}

func TestDeviceApiKeyGeneration(t *testing.T) {

	Convey("When generating new device api key", t, func() {
		result := NewDeviceKeyGen(123465, "my device")

		So(result.ClientSecret, ShouldNotBeEmpty)
		So(result.HashedKey, ShouldNotBeEmpty)

		Convey("can decode key", func() {
			keyInfo, err := Decode(result.ClientSecret)
			So(err, ShouldBeNil)

			keyHashed, err := EncodePassword(keyInfo.Key, keyInfo.Name)
			So(err, ShouldBeNil)
			So(keyHashed, ShouldEqual, result.HashedKey)
		})

		Convey("valid key", func() {
			keyInfo, err := Decode(result.ClientSecret)

			So(err, ShouldBeNil)
			b := IsValid(keyInfo, result.HashedKey)
			So(b, ShouldEqual, true)
		})
	})
}
