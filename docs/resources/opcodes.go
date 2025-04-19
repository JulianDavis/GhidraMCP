package protocol

// OpCode represents a protocol operation code
type OpCode uint32

// Protocol opcodes preserved from the original implementation
const (
	// Base opcodes
	OpNone OpCode = 0x0

	// Asset management
	OpAbandonAsset OpCode = 0xFDDBB233

	// Character and account operations
	OpActivateCharter  OpCode = 0x296C0B22
	OpActivateNPC      OpCode = 0xC9AAE81E
	OpAddReputation    OpCode = 0x7A7F1A83
	OpAddFriend        OpCode = 0x72BE5B2A
	OpAddIgnore        OpCode = 0x2A9FDFD0
	OpAddPlayerToGuild OpCode = 0x8E7AC09B

	// Authentication and session
	OpAuthenticate  OpCode = 0xDDAED1A6
	OpConnect       OpCode = 0x6CCF04D3
	OpDisconnect    OpCode = 0xFC51F550
	OpClientInitial OpCode = 0x00000060 // Initial client handshake message

	// Character actions
	OpAttack          OpCode = 0xA9EB7A65
	OpBeginCasting    OpCode = 0x9CE7D31D
	OpCancelCasting   OpCode = 0xBBE78A02
	OpCreateCharacter OpCode = 0xA2A6F203
	OpDeleteCharacter OpCode = 0x29CF4D2B

	// Movement
	OpMove           OpCode = 0xC2A10183
	OpMoveAndRotate  OpCode = 0x23BE7013
	OpMovementUpdate OpCode = 0x0ABC3210

	// Chat
	OpChat      OpCode = 0x576F5C11
	OpGuildChat OpCode = 0xB36C2222

	// Guild operations
	OpCreateGuild  OpCode = 0x7F1B3C04
	OpDisbandGuild OpCode = 0x9A3C7D11

	// Item operations
	OpDropItem    OpCode = 0x3BBE7222
	OpEquipItem   OpCode = 0xCAFE1234
	OpUnequipItem OpCode = 0xCAFE4321

	// Trade
	OpTradeRequest  OpCode = 0x87B5C123
	OpTradeResponse OpCode = 0x87B5C124
	OpTradeUpdate   OpCode = 0x87B5C125
	OpTradeAccept   OpCode = 0x87B5C126
	OpTradeCancel   OpCode = 0x87B5C127

	// World interaction
	OpInteract OpCode = 0x44BBE129
	OpUse      OpCode = 0xDEADBEEF

	// Client/Server status
	OpPing      OpCode = 0xA1B2C3D4
	OpPong      OpCode = 0xD4C3B2A1
	OpHeartbeat OpCode = 0x76543210

	// Character selection
	OpCharListRequest    OpCode = 0x12345678
	OpCharListResponse   OpCode = 0x87654321
	OpCharSelectRequest  OpCode = 0x34567890
	OpCharSelectResponse OpCode = 0x09876543

	// Server information
	OpServerInfo OpCode = 0xE1F2D3C4

	// Client handshake identification
	OpClientHandshake OpCode = 0xFA83D0A9

	// TODO: Add all remaining opcodes from the original implementation
)

// OpCodeMap maps opcodes to their string representation for logging and debugging
var OpCodeMap = map[OpCode]string{
	OpNone:               "NONE",
	OpAbandonAsset:       "ABANDONASSET",
	OpActivateCharter:    "ACTIVATECHARTER",
	OpActivateNPC:        "ACTIVATENPC",
	OpAddReputation:      "ADDREPUTATION",
	OpAddFriend:          "ADDFRIEND",
	OpAddIgnore:          "ADDIGNORE",
	OpAddPlayerToGuild:   "ADDPLAYERTOGUILD",
	OpAuthenticate:       "AUTHENTICATE",
	OpConnect:            "CONNECT",
	OpDisconnect:         "DISCONNECT",
	OpClientInitial:      "CLIENTINITIAL",
	OpAttack:             "ATTACK",
	OpBeginCasting:       "BEGINCASTING",
	OpCancelCasting:      "CANCELCASTING",
	OpCreateCharacter:    "CREATECHARACTER",
	OpDeleteCharacter:    "DELETECHARACTER",
	OpMove:               "MOVE",
	OpMoveAndRotate:      "MOVEANDROTATE",
	OpMovementUpdate:     "MOVEMENTUPDATE",
	OpChat:               "CHAT",
	OpGuildChat:          "GUILDCHAT",
	OpCreateGuild:        "CREATEGUILD",
	OpDisbandGuild:       "DISBANDGUILD",
	OpDropItem:           "DROPITEM",
	OpEquipItem:          "EQUIPITEM",
	OpUnequipItem:        "UNEQUIPITEM",
	OpTradeRequest:       "TRADEREQUEST",
	OpTradeResponse:      "TRADERESPONSE",
	OpTradeUpdate:        "TRADEUPDATE",
	OpTradeAccept:        "TRADEACCEPT",
	OpTradeCancel:        "TRADECANCEL",
	OpInteract:           "INTERACT",
	OpUse:                "USE",
	OpPing:               "PING",
	OpPong:               "PONG",
	OpHeartbeat:          "HEARTBEAT",
	OpCharSelectRequest:  "CHARSELECTREQUEST",
	OpCharSelectResponse: "CHARSELECTRESPONSE",
	OpCharListRequest:    "CHARLISTREQUEST",
	OpCharListResponse:   "CHARLISTRESPONSE",
	OpClientHandshake:    "CLIENTHANDSHAKE",
	OpServerInfo:         "SERVERINFO",
	// TODO: Add all remaining opcode mappings
}

// GetOpCodeName returns the string name of an opcode
func GetOpCodeName(code OpCode) string {
	if name, ok := OpCodeMap[code]; ok {
		return name
	}
	return "UNKNOWN"
}
