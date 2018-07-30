package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func getJWT(otpCode string) (jwt []byte, err error) {
	values := url.Values{}
	values.Set("email", "admin@barong.io")
	values.Set("password", "Qwerty123")
	values.Set("application_id", "a68be319fca51caca60eed5711226e568bd1c1d13ff452b945515f1a6ffbaca4")
	values.Set("otp_code", otpCode)

	resp, err := http.PostForm("http://auth.wb.local/api/v1/sessions", values)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	l := len(bs)
	if l < 3 || bs[0] != '"' || bs[l-1] != '"' {
		err = fmt.Errorf("invalid resp:%s", bs)
		return
	}

	jwt = bs[1 : l-1]
	return
}

func createAPIKey(otpCode string, base64PublicKey string, jwt string) (json []byte, err error) {
	values := url.Values{}
	values.Set("public_key", base64PublicKey)
	values.Set("totp_code", otpCode)

	req, err := http.NewRequest("POST", "http://auth.wb.local/api/v1/api_keys", strings.NewReader(values.Encode()))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	json, err = ioutil.ReadAll(resp.Body)
	return
}

func genPeatioJWT(kid string, jwtToken string, jwt string) (json []byte, err error) {
	values := url.Values{}
	values.Set("kid", kid)
	values.Set("jwt_token", jwtToken)

	req, err := http.NewRequest("POST", "http://auth.wb.local/api/v1/sessions/generate_jwt", strings.NewReader(values.Encode()))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+jwt)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	json, err = ioutil.ReadAll(resp.Body)
	return
}

func processCreateAPIKey(base64PublicKey, jwtBytes []byte) (kid string) {
	reader := bufio.NewReader(os.Stdin)

	os.Stdout.WriteString("Please enter the otp code for API endpoint api_keys:\n")

	otpCode, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	// create api key
	key, err := createAPIKey(otpCode[:len(otpCode)-1], string(base64PublicKey), string(jwtBytes))
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("apikey_resp", key, 0666)
	if err != nil {
		log.Fatal(err)
	}

	type apiKeyJson struct {
		Kid   string `json:"uid"`
		Error string `json:"error"`
	}
	akj := apiKeyJson{}
	err = json.Unmarshal(key, &akj)
	if err != nil {
		log.Fatal(err)
	}

	if len(akj.Error) > 0 {
		log.Fatal(akj.Error)
	}
	return akj.Kid
}

func processGetJwt() []byte {
	reader := bufio.NewReader(os.Stdin)

	os.Stdout.WriteString("Please enter the otp code for API endpoint sessions:\n")

	otpCode, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	// get jwt
	jwtBytes, err := getJWT(otpCode[:len(otpCode)-1])
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("jwt", jwtBytes, 0666)
	if err != nil {
		log.Fatal(err)
	}

	return jwtBytes
}

func genRSAKey() (privateKey *rsa.PrivateKey, base64PublicKey []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	err = privateKey.Validate()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	err = ioutil.WriteFile("private_key", privateKeyBytes, 0666)
	if err != nil {
		log.Fatal(err)
	}

	bytes, err := asn1.Marshal(privateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	publicKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: bytes,
	})

	err = ioutil.WriteFile("public_key", publicKeyBytes, 0666)
	if err != nil {
		log.Fatal(err)
	}

	base64PublicKey = make([]byte, base64.StdEncoding.EncodedLen(len(publicKeyBytes)))
	base64.StdEncoding.Encode(base64PublicKey, publicKeyBytes)
	err = ioutil.WriteFile("public_key_base64", base64PublicKey, 0666)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func randomHex(n int) (randHex string, err error) {
	b := make([]byte, n)
	i, err := rand.Read(b)
	if err != nil {
		return
	}
	if i != n {
		err = errors.New("randomHex i!=n")
		return
	}
	randHex = strings.ToUpper(hex.EncodeToString(b))
	return
}

func main() {
	privateKey, base64PublicKey := genRSAKey()

	jwtBytes := processGetJwt()

	kid := processCreateAPIKey(base64PublicKey, jwtBytes)

	hex, err := randomHex(12)
	if err != nil {
		log.Fatal(err)
	}

	now := time.Now()
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Id:        hex,
		ExpiresAt: now.Add(30 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Subject:   "session",
		Issuer:    "barong",
	})

	signedToken, err := jwtToken.SignedString(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("kid:%s token:%s jwt:%s", kid, signedToken, string(jwtBytes))

	resp, err := genPeatioJWT(kid, signedToken, string(jwtBytes))
	if err != nil {
		log.Fatal(err)
	}

	// TODO: To be finished
	log.Printf("%s", resp)

	log.Println("finish")
}
