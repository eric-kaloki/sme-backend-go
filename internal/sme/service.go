package sme

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/machakos/sme-backend-go/internal/audit"
	"github.com/machakos/sme-backend-go/internal/common"
	"github.com/machakos/sme-backend-go/pkg/crypto"
)

var (
	ErrNotFound  = errors.New("SME not found")
	ErrForbidden = errors.New("Forbidden")
)

// smeWriteRoles and smeDeleteRoles are replaced by dynamic permission checks.

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
		return val // fallback to raw on decrypt failure — don't crash the response
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

// canWriteSME checks if the requesting user has permission to create or update SMEs.
func canWriteSME(requester *common.AuthenticatedUser) bool {
	return requester.HasPermission("sme:write") || requester.HasPermission("sme:create") || requester.HasPermission("sme:update")
}

// canDeleteSME checks if the requesting user has permission to delete SMEs.
func canDeleteSME(requester *common.AuthenticatedUser) bool {
	return requester.HasPermission("sme:delete")
}

func (s *Service) CreateSME(req SmeRequest, creator *common.AuthenticatedUser) (*SME, error) {
	// 1. Security Check
	if !canWriteSME(creator) {
		return nil, ErrForbidden
	}

	// 2. XSS Sanitization
	req.BusinessName = common.Sanitize(req.BusinessName)
	req.OwnerName = common.Sanitize(req.OwnerName)
	req.Email = common.SanitizePtr(req.Email)
	req.BusinessPermitNumber = common.SanitizePtr(req.BusinessPermitNumber)
	req.Category = common.Sanitize(req.Category)
	req.SubCategory = common.SanitizePtr(req.SubCategory)
	req.SubCounty = common.Sanitize(req.SubCounty)
	req.Ward = common.Sanitize(req.Ward)
	req.MarketTown = common.SanitizePtr(req.MarketTown)
	req.BusinessAddress = common.Sanitize(req.BusinessAddress)

	// 3. Sensitive Data Encryption
	encBizName, err := crypto.Encrypt(req.BusinessName, s.cryptoKey)
	if err != nil {
		return nil, err
	}

	encOwner, err := crypto.Encrypt(req.OwnerName, s.cryptoKey)
	if err != nil {
		return nil, err
	}

	encPhone, err := crypto.Encrypt(req.Phone, s.cryptoKey)
	if err != nil {
		return nil, err
	}

	encEmail, err := s.encryptPtr(s.nilIfEmpty(req.Email))
	if err != nil {
		return nil, err
	}

	encIdNum, err := s.encryptPtr(s.nilIfEmpty(req.IDNumber))
	if err != nil {
		return nil, err
	}

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
	s.invalidateStatsCache()

	s.auditRepo.LogAsync(audit.AuditLog{
		Action:      "SME_CREATE",
		EntityType:  "SME",
		EntityID:    &smeId,
		UserID:      &creator.ID,
		Description: ptr("Created SME: " + req.BusinessName),
	})

	return s.decryptEntity(newSme), nil
}

func (s *Service) UpdateSME(id string, req SmeRequest, updater *common.AuthenticatedUser) (*SME, error) {
	// 1. Security Check
	if !canWriteSME(updater) {
		return nil, ErrForbidden
	}

	// 2. XSS Sanitization
	req.BusinessName = common.Sanitize(req.BusinessName)
	req.OwnerName = common.Sanitize(req.OwnerName)
	req.Email = common.SanitizePtr(req.Email)
	req.BusinessPermitNumber = common.SanitizePtr(req.BusinessPermitNumber)
	req.Category = common.Sanitize(req.Category)
	req.SubCategory = common.SanitizePtr(req.SubCategory)
	req.SubCounty = common.Sanitize(req.SubCounty)
	req.Ward = common.Sanitize(req.Ward)
	req.MarketTown = common.SanitizePtr(req.MarketTown)
	req.BusinessAddress = common.Sanitize(req.BusinessAddress)

	existing, err := s.repo.FindByID(id)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, ErrNotFound
	}

	encBizName, err := crypto.Encrypt(req.BusinessName, s.cryptoKey)
	if err != nil {
		return nil, err
	}
	encOwner, err := crypto.Encrypt(req.OwnerName, s.cryptoKey)
	if err != nil {
		return nil, err
	}
	encPhone, err := crypto.Encrypt(req.Phone, s.cryptoKey)
	if err != nil {
		return nil, err
	}
	encEmail, err := s.encryptPtr(s.nilIfEmpty(req.Email))
	if err != nil {
		return nil, err
	}
	encIdNum, err := s.encryptPtr(s.nilIfEmpty(req.IDNumber))
	if err != nil {
		return nil, err
	}

	existing.BusinessName = encBizName
	existing.OwnerName = encOwner
	existing.Phone = encPhone
	existing.Email = encEmail
	existing.IDNumber = encIdNum

	existing.BusinessNameHash = ptr(crypto.GenerateBlindIndex(req.BusinessName, s.blindIndexKey))
	existing.OwnerNameHash = ptr(crypto.GenerateBlindIndex(req.OwnerName, s.blindIndexKey))
	existing.PhoneHash = ptr(crypto.GenerateBlindIndex(req.Phone, s.blindIndexKey))
	existing.EmailHash = s.blindIndexPtr(s.nilIfEmpty(req.Email))
	existing.IDNumberHash = s.blindIndexPtr(s.nilIfEmpty(req.IDNumber))

	existing.BusinessPermitNumber = s.nilIfEmpty(req.BusinessPermitNumber)
	existing.Gender = req.Gender
	existing.Category = req.Category
	existing.SubCategory = req.SubCategory
	existing.PWD = req.PWD
	existing.SubCounty = req.SubCounty
	existing.Ward = req.Ward
	existing.MarketTown = req.MarketTown
	existing.BusinessAddress = req.BusinessAddress
	if req.Status != "" {
		existing.Status = req.Status
	}
	existing.UpdatedByID = updater.ID

	if err := s.repo.Update(existing); err != nil {
		return nil, err
	}
	s.invalidateStatsCache()

	s.auditRepo.LogAsync(audit.AuditLog{
		Action:      "SME_UPDATE",
		EntityType:  "SME",
		EntityID:    &id,
		UserID:      &updater.ID,
		Description: ptr("Updated SME: " + req.BusinessName),
	})

	return s.decryptEntity(existing), nil
}

func (s *Service) DeleteSME(id string, deleter *common.AuthenticatedUser) error {
	// Fix #2: Corrected to use dedicated delete-role map (was checking SME_OFFICER only).
	if !canDeleteSME(deleter) {
		return ErrForbidden
	}

	existing, err := s.repo.FindByID(id)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrNotFound
	}

	if err := s.repo.Delete(id); err != nil {
		return err
	}
	s.invalidateStatsCache()

	bizName := existing.BusinessName
	if dec, decErr := crypto.Decrypt(bizName, s.cryptoKey); decErr == nil {
		bizName = dec
	}

	s.auditRepo.LogAsync(audit.AuditLog{
		Action:      "SME_DELETE",
		EntityType:  "SME",
		EntityID:    &id,
		UserID:      &deleter.ID,
		Description: ptr("Deleted SME: " + bizName),
	})

	return nil
}

func (s *Service) SearchSMEs(searchEmail, searchPhone, status, category, subCounty, ward, gender, pwd, sortBy, sortDir string, page, size int, requester *common.AuthenticatedUser) ([]SME, int, error) {
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
	if dec, err := crypto.Decrypt(sme.BusinessName, s.cryptoKey); err == nil {
		sme.BusinessName = dec
	}
	if dec, err := crypto.Decrypt(sme.OwnerName, s.cryptoKey); err == nil {
		sme.OwnerName = dec
	}
	if dec, err := crypto.Decrypt(sme.Phone, s.cryptoKey); err == nil {
		sme.Phone = dec
	}
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

// ─────────────────────────────────────────────────────────────────────────────
// Cache & Analytics
// ─────────────────────────────────────────────────────────────────────────────

var statsCache SmeStatsOverviewResponse
var cacheExpiry int64 = 0
var cacheMutex sync.RWMutex

func (s *Service) invalidateStatsCache() {
	cacheMutex.Lock()
	cacheExpiry = 0
	cacheMutex.Unlock()
}

func (s *Service) GetStatsOverview(subCounty, ward string) (SmeStatsOverviewResponse, error) {
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

func (s *Service) GetAvailableCategories() ([]string, error) {
	return s.repo.GetDistinctList("category")
}

func (s *Service) GetAvailableSubCounties() ([]string, error) {
	return s.repo.GetDistinctList("sub_county")
}

func (s *Service) GetAvailableWards() ([]string, error) {
	return s.repo.GetDistinctList("ward")
}
