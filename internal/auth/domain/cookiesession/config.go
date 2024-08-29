package cookiesession

type CookieSessionConfig struct {
	MaxAge   int // in seconds
	Secure   bool
	HttpOnly bool
}

func NewCookieSessionConfig(maxAge int, secure bool, HttpOnly bool) *CookieSessionConfig {
	return &CookieSessionConfig{
		MaxAge:   maxAge,
		Secure:   secure,
		HttpOnly: HttpOnly,
	}
}
