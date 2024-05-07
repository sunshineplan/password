package password

import (
	"crypto/rsa"
	"time"

	"github.com/sunshineplan/utils/cache"
	"golang.org/x/crypto/bcrypt"
)

type Passworder struct {
	cache *cache.Cache
	dur   time.Duration
	max   int
	key   *rsa.PrivateKey
}

func New(d time.Duration, n int, key *rsa.PrivateKey) *Passworder {
	return &Passworder{cache.New(true), d, n, key}
}

func (p *Passworder) SetDuration(d time.Duration) { p.dur = d }
func (p *Passworder) SetMaxAttempts(n int)        { p.max = n }
func (p *Passworder) SetKey(key *rsa.PrivateKey)  { p.key = key }

func (p *Passworder) recordIncorrect(id any) error {
	var n int
	if v, ok := p.cache.Get(id); !ok {
		n = 1
	} else {
		n = v.(int) + 1
	}
	p.cache.Set(id, n, p.dur, nil)
	return incorrectPasswordError(n)
}

func (p *Passworder) IsMaxAttempts(id any) bool {
	v, ok := p.cache.Get(id)
	return ok && v.(int) >= p.max
}

func (p *Passworder) Reset(id any) {
	p.cache.Delete(id)
}

func (p *Passworder) DecryptPKCS1v15(s string) (string, error) {
	return DecryptPKCS1v15(p.key, s)
}

func (p *Passworder) compare(id any, key, password string, hash bool) (string, error) {
	if p.IsMaxAttempts(id) {
		return "", maxPasswordAttemptsError(p.max)
	}
	var err error
	if p.key != nil {
		password, err = p.DecryptPKCS1v15(password)
		if err != nil {
			return "", err
		}
	}
	if hash {
		if err = bcrypt.CompareHashAndPassword([]byte(key), []byte(password)); err != nil {
			if e := p.recordIncorrect(id); err == bcrypt.ErrMismatchedHashAndPassword {
				err = e
			}
			return "", err
		}
	} else {
		if key != password {
			return "", p.recordIncorrect(id)
		}
	}
	p.Reset(id)
	return password, nil
}

func (p *Passworder) Compare(id any, key, password string) error {
	_, err := p.compare(id, key, password, false)
	return err
}

func (p *Passworder) CompareHashAndPassword(id any, hash, password string) error {
	_, err := p.compare(id, hash, password, true)
	return err
}
