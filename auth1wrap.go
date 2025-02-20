package auth1lib

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
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

	timeoutInSecs time.Duration
	verbose       bool
}

type LoginResult struct {
	AccessToken  string
	RefreshToken string
}

type JwtSecretResult struct {
	JwtSecret []byte
	TenantKey string
	TenantId  int32
	SiteKey   string // "" if tenant-level api-key
	SiteId    int32  // 0 if tenant-level api-key
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

type auth1SiteIdKey struct {
	ID  int32
	Key string
}

type auth1SiteSpecifier func(w *auth1SiteIdKey)

func WithSiteKey(siteKey string) auth1SiteSpecifier {
	return func(w *auth1SiteIdKey) {
		w.Key = siteKey
	}
}

func WithSiteID(siteId int32) auth1SiteSpecifier {
	return func(w *auth1SiteIdKey) {
		w.ID = siteId
	}
}

func NewClient(auth1uri string, opts ...auth1WrapperOption) (*Auth1Wrapper, error) {
	parsed, err := url.ParseRequestURI(auth1uri)
	if err != nil {
		return nil, fmt.Errorf("invalid auth1 uri(%s): %v", auth1uri, err)
	}

	ret := &Auth1Wrapper{
		timeoutInSecs: time.Second * 30,
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

	ret.conn, err = grpc.NewClient(parsed.Host, grpc.WithTransportCredentials(creds))
	if err != nil {
		if ret.verbose {
			log.Printf("Auth1: grpc.Dial(%s) failed: %v\n", parsed.Host, err)
		}
		return nil, err
	}

	if ret.verbose {
		log.Printf("Auth1 URI: %s://%s@%s\n", parsed.Scheme, apikey, parsed.Host)
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

func (wrapper *Auth1Wrapper) GetJwtSecret() (*JwtSecretResult, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.GetJwtSecret(ctx, &pb.JwtSecretRequest{})
	if err != nil {
		return nil, err
	}

	return &JwtSecretResult{
		JwtSecret: r.JwtSecret,
		TenantKey: r.TenantKey,
		TenantId:  r.TenantId,
		SiteKey:   r.SiteKey,
		SiteId:    r.SiteId,
	}, nil
}

func getSiteIdOrKey(opts []auth1SiteSpecifier) (int32, string) {
	idOrKey := &auth1SiteIdKey{}
	for _, opt := range opts {
		opt(idOrKey)
	}

	if idOrKey.ID > 0 && idOrKey.Key != "" {
		panic("both site id and key provided, only one is allowed")
	}

	return idOrKey.ID, idOrKey.Key
}

func (wrapper *Auth1Wrapper) LoginUidpw(loginId string, pw []byte, opts ...auth1SiteSpecifier) (*LoginResult, error) {
	siteId, siteKey := getSiteIdOrKey(opts)

	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.LoginUidpw(ctx, &pb.LoginUidpwRequest{
		SiteKey: siteKey,
		SiteId:  siteId,
		Uid:     loginId,
		Pw:      pw,
	})
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  r.GetAtk(),
		RefreshToken: r.GetRtk(),
	}, nil
}

func (wrapper *Auth1Wrapper) LoginOneTap(token string, opts ...auth1SiteSpecifier) (*LoginResult, error) {
	siteId, siteKey := getSiteIdOrKey(opts)

	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.LoginOneTap(ctx, &pb.LoginOneTapRequest{
		SiteKey: siteKey,
		SiteId:  siteId,
		Token:   token,
	})
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  r.GetAtk(),
		RefreshToken: r.GetRtk(),
	}, nil
}

func (wrapper *Auth1Wrapper) LogoutUser(rtk string) error {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	// TODO: need site-key?
	_, err := wrapper.acli.LogoutUser(ctx, &pb.RtokenRequest{Rtk: rtk})
	return err
}

func (wrapper *Auth1Wrapper) RefreshUser(rtk string) (*LoginResult, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	// TODO: need site-key?
	r, err := wrapper.acli.RefreshUser(ctx, &pb.RtokenRequest{Rtk: rtk})
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

func (wrapper *Auth1Wrapper) AddSiteUser(loginId string, passwd []byte, memo string, opts ...auth1SiteSpecifier) (string, error) {
	siteId, siteKey := getSiteIdOrKey(opts)

	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	res, err := wrapper.acli.AddSiteUser(ctx, &pb.AddSiteUserRequest{
		SiteKey: siteKey,
		SiteId:  siteId,
		Uid:     loginId,
		Pw:      passwd,
		Memo:    memo,
	})
	if err != nil {
		return "", err
	}
	return res.GetUserKey(), nil
}

func (wrapper *Auth1Wrapper) SetUserInfo(userKey string, nick *string, email *string) (bool, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	res, err := wrapper.acli.SetUserInfo(ctx, &pb.SetUserInfoRequest{UserKey: userKey, Nick: nick, Email: email})
	if err != nil {
		return false, err
	}

	return res.GetUserKey() == userKey, nil
}

func (wrapper *Auth1Wrapper) SetUserPw(userKey string, pwOld, pwNew []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	res, err := wrapper.acli.SetUserPw(ctx, &pb.SetUserPwRequest{UserKey: userKey, PwOld: pwOld, PwNew: pwNew})
	if err != nil {
		return false, err
	}

	return res.GetUserKey() == userKey, nil
}

func (wrapper *Auth1Wrapper) SetUserPhoto(userKey string, photoUrl string) (bool, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	res, err := wrapper.acli.SetUserPhoto(ctx, &pb.SetUserPhotoRequest{UserKey: userKey, Url: photoUrl})
	if err != nil {
		return false, err
	}

	return res.GetUserKey() == userKey, nil
}

func (wrapper *Auth1Wrapper) LoginAdmin(loginId string, pw []byte) (*LoginResult, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.LoginAdmin(ctx, &pb.LoginAdminRequest{Uid: loginId, Pw: pw})
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  r.GetAtk(),
		RefreshToken: r.GetRtk(),
	}, nil
}

func (wrapper *Auth1Wrapper) RefreshAdmin(rtk string) (*LoginResult, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.RefreshAdmin(ctx, &pb.RtokenRequest{Rtk: rtk})
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:  r.GetAtk(),
		RefreshToken: r.GetRtk(),
	}, nil
}

func (wrapper *Auth1Wrapper) LogoutAdmin(rtk string) error {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	_, err := wrapper.acli.LogoutAdmin(ctx, &pb.RtokenRequest{Rtk: rtk})
	return err
}

func (wrapper *Auth1Wrapper) CreateSite(siteKey, name, memo string) (int32, error) {
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), wrapper.md), wrapper.timeoutInSecs)
	defer cancel()

	r, err := wrapper.acli.CreateSite(ctx, &pb.CreateSiteRequest{SiteKey: siteKey, Name: name, Memo: memo})
	if err != nil {
		return 0, err
	}
	return r.SiteId, nil
}
