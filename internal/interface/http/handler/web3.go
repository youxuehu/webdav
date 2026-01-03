package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"strconv"
	"github.com/yeying-community/webdav/internal/domain/user"
	"github.com/yeying-community/webdav/internal/infrastructure/auth"
	"github.com/yeying-community/webdav/internal/interface/http/dto"
	"go.uber.org/zap"
	"regexp"
    "golang.org/x/crypto/sha3"
    "math/rand"
	"fmt"
)

// Web3Handler Web3 认证处理器
type Web3Handler struct {
	web3Auth *auth.Web3Authenticator
	userRepo user.Repository
	logger   *zap.Logger
}

// NewWeb3Handler 创建 Web3 处理器
func NewWeb3Handler(
	web3Auth *auth.Web3Authenticator,
	userRepo user.Repository,
	logger *zap.Logger,
) *Web3Handler {
	return &Web3Handler{
		web3Auth: web3Auth,
		userRepo: userRepo,
		logger:   logger,
	}
}

type AddressInfo struct {
    CoinBalance string `json:"coin_balance"`
}

func HasBalance(address string) bool {
	url := "https://blockscout.yeying.pub/backend/api/v2/addresses/" + address

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var info AddressInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return false
	}

	balance, err := strconv.Atoi(info.CoinBalance)
	if err != nil {
		return false
	}

	return balance > 0
}

// 验证以太坊地址合法性
func IsValidAddress(address string) bool {
    // 1. 基础格式检查
    re := regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
    if !re.MatchString(address) {
        return false
    }
    // 2. EIP-55 校验和检查
    return verifyChecksum(address)
}

func verifyChecksum(address string) bool {
    address = strings.TrimPrefix(address, "0x")
    hash := sha3.NewLegacyKeccak256()
    hash.Write([]byte(strings.ToLower(address)))
    digest := hash.Sum(nil)
    for i := 0; i < 40; i++ {
        c := address[i]
        hashByte := digest[i/2]
        if i%2 == 0 {
            hashByte >>= 4
        } else {
            hashByte &= 0x0f
        }
        if (hashByte >= 8 && c < 'A') || (hashByte < 8 && c > '9') {
            return false
        }
    }
    return true
}

var (
    adjectives = []string{"Quick", "Lazy", "Funny", "Serious", "Brave"}
    nouns      = []string{"Fox", "Dog", "Cat", "Mouse", "Wolf"}
)

func generateHumanReadableName() string {
    rand.Seed(time.Now().UnixNano())
    adj := adjectives[rand.Intn(len(adjectives))]
    noun := nouns[rand.Intn(len(nouns))]
    num := rand.Intn(100)
    return fmt.Sprintf("%s%s%d", adj, noun, num)
}

func addUser(r *http.Request, w http.ResponseWriter, h *Web3Handler, address string) (*user.User, error) {
	// 创建用户
	userName := generateHumanReadableName()
	h.logger.Warn("userName:" + userName)
	u := user.NewUser(userName, userName)
	// 设置钱包地址
	u.SetWalletAddress(strings.ToLower(address))
	// 设置权限
	u.Permissions = user.ParsePermissions("CRUD")
	// 保存用户
	ctx := r.Context()
	if err := h.userRepo.Save(ctx, u); err != nil {
		h.logger.Error("failed to create user", zap.String("address", address))
		return nil, err
	}
	return u, nil
}

func RegisterWalletAccount(r *http.Request, w http.ResponseWriter, h *Web3Handler, address string) (*user.User, error)  {
	ctx := r.Context()
	u, err := h.userRepo.FindByWalletAddress(ctx, address)
	if err != nil {
		// 不存在，则添加
		return addUser(r, w, h, address)
	}
	return u, err
}

// HandleChallenge 处理挑战请求
// GET /api/auth/challenge?address=0x123...
func (h *Web3Handler) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	var address string

	// 获取地址参数
	switch r.Method {
	case http.MethodGet:
		address = r.URL.Query().Get("address")

	case http.MethodPost:
		var req dto.ChallengeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.sendError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
			return
		}
		address = req.Address

	default:
		h.sendError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET and POST methods are allowed")
		return
	}

	if address == "" {
		h.sendError(w, http.StatusBadRequest, "MISSING_ADDRESS", "Address parameter is required")
		return
	}

	if !IsValidAddress(address) {
		h.sendError(w, http.StatusBadRequest, "MISSING_ADDRESS", "Address parameter is invalid, address " + address)
		return
	}

	// 规范化地址
	address = strings.ToLower(strings.TrimSpace(address))

	// 检查当前钱包账户地址是否有余额
	if !HasBalance(address) {
		h.logger.Error("The balance of the web3 wallet account is 0", zap.String("address", address))
		h.sendError(w, http.StatusInternalServerError, "BALANCE_FETCH_FAIL", "The balance of the web3 wallet account is 0")
		return
	} else {
		// 注册钱包账户
		RegisterWalletAccount(r, w, h, address)
	}
	
	// 检查用户是否存在
	ctx := r.Context()
	u, err := h.userRepo.FindByWalletAddress(ctx, address)
	if err != nil {
		if err == user.ErrUserNotFound {
			h.logger.Info("wallet address not registered", zap.String("address", address))
			h.sendError(w, http.StatusNotFound, "USER_NOT_FOUND", "Wallet address not registered")
			return
		}

		h.logger.Error("failed to find user", zap.String("address", address), zap.Error(err))
		h.sendError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to process request")
		return
	}

	// 创建挑战
	challenge, err := h.web3Auth.CreateChallenge(address)
	if err != nil {
		h.logger.Error("failed to create challenge", zap.String("address", address), zap.Error(err))
		h.sendError(w, http.StatusInternalServerError, "CHALLENGE_CREATION_FAILED", "Failed to create challenge")
		return
	}

	h.logger.Info("challenge created",
		zap.String("address", address),
		zap.String("username", u.Username),
		zap.String("nonce", challenge.Nonce))

	// 返回挑战
	response := dto.ChallengeResponse{
		Nonce:     challenge.Nonce,
		Message:   challenge.Message,
		ExpiresAt: challenge.ExpiresAt,
	}

	h.sendJSON(w, http.StatusOK, response)
}

// HandleVerify 处理验证请求
// POST /api/auth/verify
func (h *Web3Handler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.sendError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only POST method is allowed")
		return
	}

	// 解析请求
	var req dto.VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("invalid request body", zap.Error(err))
		h.sendError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	// 验证必填字段
	if req.Address == "" {
		h.sendError(w, http.StatusBadRequest, "MISSING_ADDRESS", "Address is required")
		return
	}

	if req.Signature == "" {
		h.sendError(w, http.StatusBadRequest, "MISSING_SIGNATURE", "Signature is required")
		return
	}

	// 规范化地址
	req.Address = strings.ToLower(strings.TrimSpace(req.Address))

	// 查找用户
	ctx := r.Context()
	u, err := h.userRepo.FindByWalletAddress(ctx, req.Address)
	if err != nil {
		if err == user.ErrUserNotFound {
			h.logger.Info("wallet address not registered", zap.String("address", req.Address))
			h.sendError(w, http.StatusNotFound, "USER_NOT_FOUND", "Wallet address not registered")
			return
		}

		h.logger.Error("failed to find user", zap.String("address", req.Address), zap.Error(err))
		h.sendError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to process request")
		return
	}

	// 验证签名并生成 token
	token, err := h.web3Auth.VerifySignature(ctx, req.Address, req.Signature)
	if err != nil {
		h.logger.Warn("signature verification failed",
			zap.String("address", req.Address),
			zap.Error(err))
		h.sendError(w, http.StatusUnauthorized, "INVALID_SIGNATURE", "Signature verification failed")
		return
	}

	h.logger.Info("user authenticated via web3",
		zap.String("address", req.Address),
		zap.String("username", u.Username))

	// 构建响应
	response := dto.VerifyResponse{
		Token:     token.Value,
		ExpiresAt: token.ExpiresAt,
		User: &dto.UserInfo{
			Username:      u.Username,
			WalletAddress: u.WalletAddress,
			Permissions:   h.getPermissionStrings(u.Permissions),
		},
	}

	h.sendJSON(w, http.StatusOK, response)
}

func (h *Web3Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	// TODO:
}

// getPermissionStrings 获取权限字符串列表
func (h *Web3Handler) getPermissionStrings(perms *user.Permissions) []string {
	var permissions []string

	if perms.Create {
		permissions = append(permissions, "create")
	}
	if perms.Read {
		permissions = append(permissions, "read")
	}
	if perms.Update {
		permissions = append(permissions, "update")
	}
	if perms.Delete {
		permissions = append(permissions, "delete")
	}

	return permissions
}

// sendJSON 发送 JSON 响应
func (h *Web3Handler) sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
	}
}

// sendError 发送错误响应
func (h *Web3Handler) sendError(w http.ResponseWriter, status int, code, message string) {
	response := dto.NewErrorResponse(code, message)
	h.sendJSON(w, status, response)
}
