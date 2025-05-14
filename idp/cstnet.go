package idp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

type CSTNETIdProvider struct {
	Client *http.Client
	Config *oauth2.Config
}

func NewCSTNETIdProvider(clientId string, clientSecret string, redirectUrl string) *CSTNETIdProvider {
	idp := &CSTNETIdProvider{}
	idp.Config = idp.getConfig(clientId, clientSecret, redirectUrl)
	return idp
}

func (idp *CSTNETIdProvider) SetHttpClient(client *http.Client) {
	idp.Client = client
}

func (idp *CSTNETIdProvider) getConfig(clientId string, clientSecret string, redirectUrl string) *oauth2.Config {
	endpoint := oauth2.Endpoint{
		AuthURL:  "https://passport.escience.cn/oauth2/authorize",
		TokenURL: "https://passport.escience.cn/oauth2/token",
	}

	config := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  redirectUrl,
		Scopes:       []string{"all"},
		Endpoint:     endpoint,
	}

	return config
}

func (idp *CSTNETIdProvider) GetToken(code string) (*oauth2.Token, error) {
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", code)
	values.Set("client_id", idp.Config.ClientID)
	values.Set("client_secret", idp.Config.ClientSecret)
	values.Set("redirect_uri", idp.Config.RedirectURL)

	resp, err := idp.Client.PostForm(idp.Config.Endpoint.TokenURL, values)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}

	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	return token, nil
}

type CSTNETUserInfo struct {
	UmtId           string   `json:"umtId"`
	Truename        string   `json:"truename"`
	Type            string   `json:"type"`
	SecurityEmail   string   `json:"securityEmail"`
	CstnetIdStatus  string   `json:"cstnetIdStatus"`
	PasswordType    string   `json:"passwordType"`
	CstnetId        string   `json:"cstnetId"`
	SecondaryEmails []string `json:"secondaryEmails"`
}

func (idp *CSTNETIdProvider) GetUserInfo(token *oauth2.Token) (*UserInfo, error) {
	url := "https://passport.escience.cn/oauth2/userinfo"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := idp.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var cstnetInfo CSTNETUserInfo
	err = json.Unmarshal(body, &cstnetInfo)
	if err != nil {
		return nil, err
	}

	userInfo := &UserInfo{
		Id:          cstnetInfo.UmtId,
		Username:    cstnetInfo.CstnetId,
		DisplayName: cstnetInfo.Truename,
		Email:       cstnetInfo.CstnetId,
		AvatarUrl:   "", // CSTNET doesn't provide avatar information
	}

	return userInfo, nil
}
