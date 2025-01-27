package auth1lib

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	pb "github.com/shkim/auth1lib-go/rpcapi"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type Auth1Wrapper struct {
	conn *grpc.ClientConn
	md   metadata.MD
	acli pb.Auth1Client

	targetTenantKey string
	targetSiteKey   string

	timeoutInSecs time.Duration
	verbose       bool
}

type LoginResult struct {
	AccessToken  string
	RefreshToken string
}

type auth1WrapperOption func(w *Auth1Wrapper)

func WithVerbose() auth1WrapperOption {
	return func(w *Auth1Wrapper) {
		w.verbose = true
	}
}

func WithRequestTimeout(seconds int) auth1WrapperOption {
	return func(w *Auth1Wrapper) {
		w.timeoutInSecs = time.Duration(seconds) * time.Second
	}
}

func NewClient(auth1uri string, opts ...auth1WrapperOption) (*Auth1Wrapper, error) {
	parsed, err := url.ParseRequestURI(auth1uri)
	if err != nil {
		return nil, fmt.Errorf("invalid auth1 uri(%s): %v", auth1uri, err)
	}
	tenantAndSite := strings.Split(strings.TrimSuffix(strings.TrimPrefix(parsed.Path, "/"), "/"), "/")
	if len(tenantAndSite) != 2 {
		return nil, fmt.Errorf("invalid auth1 uri path(/tenant/site): %s", parsed.Path)
	}

	ret := &Auth1Wrapper{
		timeoutInSecs:   time.Second * 30, // default
		targetTenantKey: tenantAndSite[0],
		targetSiteKey:   tenantAndSite[1],
	}

	var creds credentials.TransportCredentials
	if parsed.Scheme == "auth1s" {
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: false})
	} else if parsed.Scheme == "auth1" {
		creds = insecure.NewCredentials()
	} else {
		return nil, fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}

	apikey := parsed.User.Username()
	secret, hasPw := parsed.User.Password()
	if apikey != "" && hasPw {
		ret.SetApiKey(apikey, secret)
	}

	for _, opt := range opts {
		opt(ret)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ret.conn, err = grpc.DialContext(ctx, parsed.Host, grpc.WithTransportCredentials(creds))
	if err != nil {
		if ret.verbose {
			log.Printf("Auth1: grpc.Dial(%s) failed: %v\n", parsed.Host, err)
		}
		return nil, err
	}

	ret.acli = pb.NewAuth1Client(ret.conn)
	return ret, nil
}

func (wrapper *Auth1Wrapper) Close() error {
	if wrapper.conn != nil {
		err := wrapper.conn.Close()
		wrapper.conn = nil
		if err != nil {
			if wrapper.verbose {
				log.Printf("Auth1: gRPC ClientConn.Close failed: %v\n", err)
			}
			return err
		}
	} else if wrapper.verbose {
		log.Println("Auth1: already closed.")
	}
	return nil
}

func (wrapper *Auth1Wrapper) SetApiKey(apikey, secret string) {
	wrapper.md = metadata.Pairs("apikey", apikey, "secret", secret)
}

func (wrapper *Auth1Wrapper) GetTenantKey() string {
	return wrapper.targetTenantKey
}

func (wrapper *Auth1Wrapper) GetSiteKey() string {
	return wrapper.targetSiteKey
}

func (wrapper *Auth1Wrapper) GetSiteJwtSecret() ([]byte, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.GetSiteJwtSecret(ctx, &pb.SiteJwtSecretRequest{SiteKey: wrapper.targetSiteKey})
	if err != nil {
		return nil, err
	}

	return r.GetJwtSecret(), nil
}

func (wrapper *Auth1Wrapper) LoginUidpw(uid string, pw []byte) (*LoginResult, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.LoginUidpw(ctx, &pb.LoginUidpwRequest{SiteKey: wrapper.targetSiteKey, Uid: uid, Pw: pw})
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  r.GetAtk(),
		RefreshToken: r.GetRtk(),
	}, nil
}

func (wrapper *Auth1Wrapper) LoginNoAuth(uid string) (*LoginResult, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.LoginNoAuth(ctx, &pb.LoginNoAuthRequest{SiteKey: wrapper.targetSiteKey, Uid: uid})
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  r.GetAtk(),
		RefreshToken: r.GetRtk(),
	}, nil
}

func (wrapper *Auth1Wrapper) LoginOneTap(token string) (*LoginResult, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.LoginOneTap(ctx, &pb.LoginOneTapRequest{SiteKey: wrapper.targetSiteKey, Token: token})
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  r.GetAtk(),
		RefreshToken: r.GetRtk(),
	}, nil
}

func (wrapper *Auth1Wrapper) Logout(rtk string) error {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	_, err := wrapper.acli.LogoutUser(ctx, &pb.RtokenRequest{SiteKey: wrapper.targetSiteKey, Rtk: rtk})
	return err
}

func (wrapper *Auth1Wrapper) RefreshAuth(rtk string) (*LoginResult, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.RefreshUser(ctx, &pb.RtokenRequest{SiteKey: wrapper.targetSiteKey, Rtk: rtk})
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  r.GetAtk(),
		RefreshToken: r.GetRtk(),
	}, nil
}

func (wrapper *Auth1Wrapper) GetUserInfo(userKey string) (*pb.UserInfoReply, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	return wrapper.acli.GetUserInfo(ctx, &pb.UserInfoRequest{UserKey: userKey})
}

func (wrapper *Auth1Wrapper) AddSiteUser(siteKey, userId string, passwd []byte, memo string, noauth bool) (string, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	res, err := wrapper.acli.AddSiteUser(ctx, &pb.AddSiteUserRequest{SiteKey: siteKey, Uid: userId, Pw: passwd, Memo: memo, Noauth: noauth})
	if err != nil {
		return "", err
	}
	return res.GetUserKey(), nil
}
