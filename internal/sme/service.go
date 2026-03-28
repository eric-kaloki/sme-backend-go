package sme

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/machakos/sme-backend-go/internal/audit"
	"github.com/machakos/sme-backend-go/internal/user"
	"github.com/machakos/sme-backend-go/pkg/crypto"
)

var (
	ErrNotFound = errors.New("sme not found")
	ErrForbidden = errors.New("forbidden")
)

type Service struct {
	repo          *Repository
	auditRepo     *audit.Repository
	cryptoKey     string
	blindIndexKey string
}

func NewService(repo *Repository, auditRepo *audit.Repository, cryptoKey, blindIndexKey string) *Service {
	return &Service{
		repo:          repo,
		auditRepo:     auditRepo,
		cryptoKey:     cryptoKey,
		blindIndexKey: blindIndexKey,
	}
}

func (s *Service) encryptPtr(val *string) (*string, error) {
	if val == nil || *val == "" {
		return val, nil
	}
	enc, err := crypto.Encrypt(*val, s.cryptoKey)
	return &enc, err
}

func (s *Service) decryptPtr(val *string) *string {
	if val == nil || *val == "" {
		return val
	}
	dec, err := crypto.Decrypt(*val, s.cryptoKey)
	if err != nil {
		return val // fallback to raw
	}
	return &dec
}

func (s *Service) blindIndexPtr(val *string) *string {
	if val == nil || *val == "" {
		return nil
	}
	idx := crypto.GenerateBlindIndex(*val, s.blindIndexKey)
	return &idx
}

func (s *Service) CreateSME(req SmeRequest, creator *user.User) (*SME, error) {
	// Encrypt required fields
	encBizName, err := crypto.Encrypt(req.BusinessName, s.cryptoKey)
	if err != nil { return nil, err }

	encOwner, err := crypto.Encrypt(req.OwnerName, s.cryptoKey)
	if err != nil { return nil, err }

	encPhone, err := crypto.Encrypt(req.Phone, s.cryptoKey)
	if err != nil { return nil, err }

	// Encrypt optional
	encEmail, err := s.encryptPtr(s.nilIfEmpty(req.Email))
	if err != nil { return nil, err }
	encIdNum, err := s.encryptPtr(s.nilIfEmpty(req.IDNumber))
	if err != nil { return nil, err }

	smeId := uuid.NewString()

	newSme := &SME{
		ID:                   smeId,
		BusinessName:         encBizName,
		OwnerName:            encOwner,
		Phone:                encPhone,
		Email:                encEmail,
		IDNumber:             encIdNum,
		BusinessNameHash:     ptr(crypto.GenerateBlindIndex(req.BusinessName, s.blindIndexKey)),
		OwnerNameHash:        ptr(crypto.GenerateBlindIndex(req.OwnerName, s.blindIndexKey)),
		PhoneHash:            ptr(crypto.GenerateBlindIndex(req.Phone, s.blindIndexKey)),
		EmailHash:            s.blindIndexPtr(s.nilIfEmpty(req.Email)),
		IDNumberHash:         s.blindIndexPtr(s.nilIfEmpty(req.IDNumber)),
		BusinessPermitNumber: s.nilIfEmpty(req.BusinessPermitNumber),
		Gender:               req.Gender,
		Category:             req.Category,
		SubCategory:          req.SubCategory,
		PWD:                  req.PWD,
		SubCounty:            req.SubCounty,
		Ward:                 req.Ward,
		MarketTown:           req.MarketTown,
		BusinessAddress:      req.BusinessAddress,
		Status:               "ACTIVE",
		CreatedByID:          creator.ID,
		UpdatedByID:          creator.ID,
	}

	if err := s.repo.Create(newSme); err != nil {
		return nil, err
	}

	// Audit log
	s.auditRepo.LogAsync(audit.AuditLog{
		Action:      "SME_CREATE",
		EntityType:  "SME",
		EntityID:    &smeId,
		UserID:      &creator.ID,
		Description: ptr("Created SME: " + req.BusinessName),
	})

	// Decrypt immediately before returning to handler
	return s.decryptEntity(newSme), nil
}

func (s *Service) SearchSMEs(searchEmail, searchPhone, status, category, subCounty, ward, gender, pwd, sortBy, sortDir string, page, size int, requester *user.User) ([]SME, int, error) {
	// 1. Convert plaintext searches into blind index hashes!
	var emailHash, phoneHash string
	if searchEmail != "" {
		emailHash = crypto.GenerateBlindIndex(searchEmail, s.blindIndexKey)
	}
	if searchPhone != "" {
		phoneHash = crypto.GenerateBlindIndex(searchPhone, s.blindIndexKey)
	}

	smes, total, err := s.repo.SearchSMEs(emailHash, phoneHash, status, category, subCounty, ward, gender, pwd, sortBy, sortDir, page, size)
	if err != nil {
		return nil, 0, err
	}

	for i := range smes {
		smes[i] = *s.decryptEntity(&smes[i])
	}
	return smes, total, nil
}

func (s *Service) decryptEntity(sme *SME) *SME {
	// Safely decrypts in place ignoring errors (returns cipher if decryption fails to avoid crashing entire payload)
	if dec, err := crypto.Decrypt(sme.BusinessName, s.cryptoKey); err == nil { sme.BusinessName = dec }
	if dec, err := crypto.Decrypt(sme.OwnerName, s.cryptoKey); err == nil { sme.OwnerName = dec }
	if dec, err := crypto.Decrypt(sme.Phone, s.cryptoKey); err == nil { sme.Phone = dec }
	sme.Email = s.decryptPtr(sme.Email)
	sme.IDNumber = s.decryptPtr(sme.IDNumber)
	return sme
}

func (s *Service) nilIfEmpty(val *string) *string {
	if val != nil && *val == "" {
		return nil
	}
	return val
}

func ptr(s string) *string { return &s }

// -------------------------------------------------------------------------------------------------
// Cache & Analytics Management
// -------------------------------------------------------------------------------------------------

var statsCache SmeStatsOverviewResponse
var cacheExpiry int64 = 0
var cacheMutex sync.RWMutex

func (s *Service) GetStatsOverview(subCounty, ward string) (SmeStatsOverviewResponse, error) {
	// Only cache the raw un-filtered dashboard overview.
	if subCounty == "" && ward == "" {
		cacheMutex.RLock()
		if time.Now().Unix() < cacheExpiry {
			defer cacheMutex.RUnlock()
			return statsCache, nil
		}
		cacheMutex.RUnlock()
	}

	response, err := s.repo.GetStatsOverview(subCounty, ward)
	if err != nil {
		return response, err
	}

	if subCounty == "" && ward == "" {
		cacheMutex.Lock()
		statsCache = response
		cacheExpiry = time.Now().Add(60 * time.Second).Unix()
		cacheMutex.Unlock()
	}

	return response, nil
}

func (s *Service) GetAvailableCategories() ([]string, error) { return s.repo.GetDistinctList("category") }
func (s *Service) GetAvailableSubCounties() ([]string, error) { return s.repo.GetDistinctList("sub_county") }
func (s *Service) GetAvailableWards() ([]string, error) { return s.repo.GetDistinctList("ward") }

